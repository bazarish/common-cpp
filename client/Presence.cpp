// Bazarish project (c) 2026
#include "Presence.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>

namespace bazarish::client {

namespace {

using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;
using std::chrono::seconds;

constexpr std::uint8_t kWatchType = 1;
constexpr std::uint8_t kRenewType = 2;
constexpr std::uint8_t kStateType = 3;
constexpr std::uint8_t kToHolder = 1;
constexpr std::uint8_t kFromHolder = 2;
constexpr std::size_t kTypeBytes = 1;
constexpr std::size_t kHeaderBytes = kTypeBytes + kPresenceSubscriptionIdBytes;
constexpr std::size_t kSequenceBytes = 8;
constexpr std::size_t kBitsPerByte = 8;
constexpr std::size_t kSubscriptionKeyBytes = kAeadKeyBytes;
constexpr char kWatchTag[] = "presence.watch";
constexpr char kWatchDomain[] = "bazarish presence watch v1";
constexpr char kWatchSignatureField[] = "sig";

constexpr std::int64_t kWatchSkewSeconds = 120;
constexpr milliseconds kReceiveSlice{250};
constexpr char kPresenceAddressLabel[] = "Presence address";
constexpr char kPresenceWatcherLabel[] = "Presence watcher";

std::atomic<std::uint64_t> g_lastPresenceId{0};

Bytes nonceFor(const std::uint8_t direction, const std::uint64_t sequence)
{
    Bytes nonce(kAeadNonceBytes, 0);
    nonce[0] = direction;
    for (std::size_t index = 0; index < kSequenceBytes; ++index) {
        nonce[kAeadNonceBytes - 1 - index]
            = static_cast<std::uint8_t>(sequence >> (index * kBitsPerByte));
    }
    return nonce;
}

std::uint64_t sequenceOf(const Bytes& nonce)
{
    std::uint64_t sequence = 0;
    for (std::size_t index = kAeadNonceBytes - kSequenceBytes; index < kAeadNonceBytes; ++index) {
        sequence = (sequence << kBitsPerByte) | nonce[index];
    }
    return sequence;
}

Bytes headerFor(const std::uint8_t type, const Bytes& id)
{
    if (id.size() != kPresenceSubscriptionIdBytes) {
        throw std::invalid_argument("a presence subscription id is 8 bytes");
    }
    Bytes header(kHeaderBytes);
    header[0] = type;
    std::copy(id.begin(), id.end(), header.begin() + kTypeBytes);
    return header;
}

std::uint64_t subscriptionOf(const Bytes& id)
{
    std::uint64_t subscription = 0;
    for (const unsigned char byte : id) {
        subscription = (subscription << kBitsPerByte) | byte;
    }
    return subscription;
}

Bytes watchSigningInput(const nlohmann::json& unsignedWatch)
{
    Bytes input(kWatchDomain, kWatchDomain + sizeof(kWatchDomain) - 1);
    const Bytes encoded = nlohmann::json::to_cbor(unsignedWatch);
    input.insert(input.end(), encoded.begin(), encoded.end());
    return input;
}

Bytes sealedFrame(const std::uint8_t type, const Bytes& id, const Bytes& key,
    const std::uint8_t direction, const std::uint64_t sequence, const nlohmann::json& payload)
{
    Bytes frame = headerFor(type, id);
    const Bytes nonce = nonceFor(direction, sequence);
    const Bytes sealed = aeadSeal(key, nonce, nlohmann::json::to_cbor(payload));
    frame.insert(frame.end(), nonce.begin(), nonce.end());
    frame.insert(frame.end(), sealed.begin(), sealed.end());
    return frame;
}

std::optional<nlohmann::json> openedFrame(const Bytes& frame, const Bytes& key,
    const std::uint8_t direction, std::uint64_t& lastSequence)
{
    if (frame.size() < kHeaderBytes + kAeadNonceBytes + kAeadTagBytes) {
        return std::nullopt;
    }
    const Bytes nonce(frame.begin() + kHeaderBytes, frame.begin() + kHeaderBytes + kAeadNonceBytes);
    const std::uint64_t sequence = sequenceOf(nonce);
    if (nonce[0] != direction || sequence <= lastSequence) {
        return std::nullopt;
    }
    const std::optional<Bytes> plain
        = aeadOpen(key, nonce, Bytes(frame.begin() + kHeaderBytes + kAeadNonceBytes, frame.end()));
    if (!plain) {
        return std::nullopt;
    }
    lastSequence = sequence;
    return parseCbor(*plain);
}

class I2pPresenceLink final : public PresenceLink {
public:
    I2pPresenceLink(i2p::Router& router, std::shared_ptr<i2p::Endpoint> endpoint)
        : router_(router)
        , endpoint_(std::move(endpoint))
        , looksUp_(router.capabilities().leaseSetRefresh)
    {
    }

    ~I2pPresenceLink() override
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        lookupAsked_.notify_all();
        endpoint_->stop();
        if (lookups_.joinable()) {
            lookups_.join();
        }
    }

    std::string host() const override
    {
        return endpoint_->routingHost();
    }

    void send(const std::string& host, const Bytes& datagram) override
    {
        endpoint_->sendRawDatagram(host, datagram);
    }

    void sendAfterLookup(const std::string& host, const Bytes& datagram) override
    {
        // SAM has no lookup past the cache: a stale lease set holds there until it expires.
        if (!looksUp_) {
            send(host, datagram);
            return;
        }
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            pending_[host] = datagram;
            if (!lookups_.joinable()) {
                lookups_ = std::thread([this]() { lookUp(); });
            }
        }
        lookupAsked_.notify_all();
    }

    bool lost() const override
    {
        return endpoint_->lost();
    }

    std::optional<Bytes> receive(const milliseconds wait) override
    {
        std::vector<std::uint8_t> got = endpoint_->receiveRawDatagram(wait);
        if (got.empty()) {
            return std::nullopt;
        }
        return Bytes(got.begin(), got.end());
    }

private:
    void lookUp()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        while (true) {
            lookupAsked_.wait(lock, [this]() { return stopping_ || !pending_.empty(); });
            if (stopping_) {
                return;
            }
            const auto [host, datagram] = *pending_.begin();
            pending_.erase(pending_.begin());
            lock.unlock();
            try {
                if (router_.refreshLeaseSet(endpoint_->routingHost(), host).after.has_value()) {
                    send(host, datagram);
                }
            } catch (const std::exception& error) {
                bazarish::log::info("presence: a looked-up datagram was not sent: {}", error.what());
            }
            lock.lock();
        }
    }

    i2p::Router& router_;
    std::shared_ptr<i2p::Endpoint> endpoint_;
    const bool looksUp_;
    std::mutex mutex_;
    std::condition_variable lookupAsked_;
    std::map<std::string, Bytes> pending_;
    bool stopping_ = false;
    std::thread lookups_;
};

struct Outgoing {
    std::string peer;
    std::string host;
    Bytes id;
    Bytes key;
    std::uint64_t sent = 0;
    std::uint64_t heard = 0;
    bool answered = false;
    bool sentBefore = false;
    Clock::time_point lastSent{};
    Clock::time_point lastHeard{};
    // Online seen before a renew went unanswered stands until the contact answers or until then.
    Clock::time_point carriedUntil{};
    PresenceState state;
};

struct Incoming {
    std::string peer;
    std::string reply;
    Bytes id;
    Bytes key;
    std::uint64_t sent = 0;
    std::uint64_t heard = 0;
    Clock::time_point expires{};
    std::optional<PresenceState> told;
};

}  // namespace

Bytes presenceWatchFrame(const PresenceWatch& watch, const Key& signer, const EpochPublic& recipient)
{
    nlohmann::json content = {
        {"t", kWatchTag},
        {"from", watch.from},
        {"dev", watch.device},
        {"reply", watch.reply},
        {"sub", toHex(watch.id)},
        {"key", toBase64(watch.key)},
        {"sentAt", watch.sentAt},
    };
    content[kWatchSignatureField] = nlohmann::json::binary(sign(signer, watchSigningInput(content)));
    const Bytes sealed = sealToEpoch(nlohmann::json::to_cbor(content), recipient);
    Bytes frame = headerFor(kWatchType, watch.id);
    frame.insert(frame.end(), sealed.begin(), sealed.end());
    return frame;
}

i2p::EndpointConfig presenceEndpointShape()
{
    i2p::EndpointConfig endpoint;
    endpoint.privacy = tunnelPrivacy();
    endpoint.tunnelQuantity = i2p::kDefaultTunnelQuantity;
    endpoint.published = true;
    endpoint.traffic = i2p::Traffic::eRaw;
    return endpoint;
}

PresenceNet i2pPresenceNet(std::filesystem::path routerDir, std::string accountLabel)
{
    return [routerDir = std::move(routerDir), accountLabel = std::move(accountLabel)](
               const PresenceLinkConfig& config) -> std::unique_ptr<PresenceLink> {
        i2p::Router& router = sharedI2pRouter(routerDir);
        const bool watching = !config.keys.has_value() && !config.readerKey.empty();
        i2p::EndpointConfig endpoint = presenceEndpointShape();
        if (watching) {
            if (std::shared_ptr<i2p::Endpoint> warm = acquireWarmWatcher(endpoint.privacy)) {
                warm->setLeaseSetReaderKey(config.readerKey);
                router.retagEndpoint(*warm, kPresenceWatcherLabel, accountLabel);
                return std::make_unique<I2pPresenceLink>(router, std::move(warm));
            }
        }
        endpoint.label = watching ? kPresenceWatcherLabel : kPresenceAddressLabel;
        endpoint.keys = config.keys;
        endpoint.accountLabel = accountLabel;
        endpoint.leaseSetReaders = config.readers;
        endpoint.leaseSetReaderKey = config.readerKey;
        return std::make_unique<I2pPresenceLink>(router, router.createEndpoint(endpoint));
    };
}

struct Presence::Impl {
    struct Runner {
        std::unique_ptr<PresenceLink> link;
        std::thread reader;
        std::atomic<bool> stopping{false};
    };

    struct HolderLane {
        std::unique_ptr<Runner> runner;
        std::deque<Bytes> inbox;
        std::vector<Bytes> readers;
        std::vector<Bytes> wanted;
        Clock::time_point readersChanged{};
        Clock::time_point raiseAfter{};
        std::map<std::uint64_t, Incoming> incoming;
    };

    struct WatcherLane {
        std::unique_ptr<Runner> runner;
        std::deque<Bytes> inbox;
        std::map<std::string, Outgoing> peers;
    };

    PresenceAccount account;
    PresenceTimings timings;
    const std::uint64_t id = ++g_lastPresenceId;
    Identity identity;
    std::shared_ptr<const EpochRing> ring;
    PresenceSeed seed;
    PresenceNet net;
    PresenceSink sink;

    std::mutex mutex;
    std::condition_variable wake;
    std::condition_variable left;
    bool stopping = false;
    std::uint64_t leftThrough = 0;
    struct Inputs {
        bool focused = false;
        bool away = false;
        std::uint64_t leaveAsked = 0;
        bool shown = true;
        std::vector<PresenceContact> contacts;
        std::uint64_t contactsVersion = 0;
        std::vector<std::string> watched;
        std::map<std::string, Clock::time_point> typingUntil;
    } inputs;

    bool focused = false;
    bool away = false;
    bool shown = true;
    std::vector<PresenceContact> contacts;
    std::uint64_t contactsVersion = 0;
    std::vector<std::string> watched;
    std::map<std::string, Clock::time_point> typingUntil;

    std::map<PresenceDay, HolderLane> holders;
    std::map<PresenceDay, WatcherLane> watchers;
    std::map<std::string, PresenceState> shownStates;
    Clock::time_point lastOnline{};
    std::thread worker;

    Impl(PresenceAccount accountIn, PresenceNet netIn, PresenceSink sinkIn,
        PresenceTimings timingsIn)
        : account(std::move(accountIn))
        , timings(std::move(timingsIn))
        , identity(Identity::fromPrivatePem(account.deviceSigningPem))
        , ring(account.ring)
        , seed(std::exchange(account.seed, {}))
        , net(std::move(netIn))
        , sink(std::move(sinkIn))
    {
        inputs.shown = account.shown;
        shown = account.shown;
        setPresenceWanted(id, account.shown);
        worker = std::thread([this]() { run(); });
    }

    ~Impl()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            stopping = true;
        }
        wake.notify_all();
        worker.join();
        setPresenceWanted(id, false);
    }

    static std::vector<PresenceDay> liveDays(const std::int64_t utc)
    {
        const PresenceDay ending = presenceDayOf(utc - kPresenceHalfOverlapSeconds);
        const PresenceDay starting = presenceDayOf(utc + kPresenceHalfOverlapSeconds);
        if (ending == starting) {
            return {ending};
        }
        return {ending, starting};
    }

    std::unique_ptr<Runner> openRunner(const PresenceLinkConfig& config, std::deque<Bytes>& inbox)
    {
        auto runner = std::make_unique<Runner>();
        runner->link = net(config);
        runner->reader = std::thread([this, &held = *runner, &inbox]() {
            while (!held.stopping.load() && !held.link->lost()) {
                std::optional<Bytes> got = held.link->receive(kReceiveSlice);
                if (!got) {
                    continue;
                }
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    inbox.push_back(std::move(*got));
                }
                wake.notify_all();
            }
        });
        return runner;
    }

    static void closeRunner(std::unique_ptr<Runner>& runner)
    {
        if (!runner) {
            return;
        }
        runner->stopping.store(true);
        runner->reader.join();
        runner.reset();
    }

    std::optional<std::reference_wrapper<const PresenceContact>> contactFor(
        const std::string& fingerprint) const
    {
        const auto found = std::find_if(contacts.begin(), contacts.end(),
            [&fingerprint](const PresenceContact& contact) { return contact.fingerprint == fingerprint; });
        if (found == contacts.end()) {
            return std::nullopt;
        }
        return std::cref(*found);
    }

    template <typename Visit>
    void forEachReader(const PresenceDay day, const Visit& visit) const
    {
        std::size_t counted = 0;
        for (const PresenceContact& contact : contacts) {
            if (counted == kMaxPresenceReaders) {
                return;
            }
            if (const std::optional<ScheduledDay> scheduled = scheduledOn(contact.schedule, day)) {
                ++counted;
                visit(contact, *scheduled);
            }
        }
    }

    bool readsOn(const std::string& fingerprint, const PresenceDay day) const
    {
        bool reads = false;
        forEachReader(day, [&](const PresenceContact& contact, const ScheduledDay&) {
            reads = reads || contact.fingerprint == fingerprint;
        });
        return reads;
    }

    std::vector<Bytes> readersWanted(const PresenceDay day) const
    {
        std::vector<Bytes> readers;
        forEachReader(day, [&readers](const PresenceContact&, const ScheduledDay& scheduled) {
            readers.push_back(scheduled.reader);
        });
        return readers;
    }

    // Which contacts read is what counts: a new order of the chat list must not re-create the address.
    static bool sameReaders(const std::vector<Bytes>& left, const std::vector<Bytes>& right)
    {
        return left.size() == right.size()
            && std::is_permutation(left.begin(), left.end(), right.begin());
    }

    bool watching(const std::string& peerFp) const
    {
        return std::find(watched.begin(), watched.end(), peerFp) != watched.end();
    }

    void send(Runner& runner, const std::string& host, const Bytes& datagram)
    {
        try {
            runner.link->send(host, datagram);
        } catch (const std::exception& error) {
            bazarish::log::info("presence: a datagram was not sent: {}", error.what());
        }
    }

    void sendAfterLookup(Runner& runner, const std::string& host, const Bytes& datagram)
    {
        try {
            runner.link->sendAfterLookup(host, datagram);
        } catch (const std::exception& error) {
            bazarish::log::info("presence: a datagram was not sent: {}", error.what());
        }
    }

    static Outgoing outgoingTo(const PresenceContact& contact, const std::string& host)
    {
        Outgoing outgoing;
        outgoing.peer = contact.fingerprint;
        outgoing.host = host;
        rewatch(outgoing);
        return outgoing;
    }

    static void rewatch(Outgoing& outgoing)
    {
        outgoing.id = randomBytes(kPresenceSubscriptionIdBytes);
        outgoing.key = randomBytes(kSubscriptionKeyBytes);
        outgoing.sent = 0;
        outgoing.heard = 0;
        outgoing.answered = false;
    }

    void carry(Outgoing& outgoing, const Clock::time_point now) const
    {
        if (outgoing.state.online) {
            outgoing.state.typing = false;
            outgoing.carriedUntil = now + timings.subscriptionLife;
        }
    }

    void sendWatch(WatcherLane& lane, Outgoing& outgoing, const Clock::time_point now)
    {
        const auto contact = contactFor(outgoing.peer);
        const std::int64_t utc = timings.utcNow();
        const std::optional<EpochPublic> epoch
            = contact.has_value() ? epochFor(contact->get().epochs, utc) : std::nullopt;
        if (!epoch.has_value()) {
            bazarish::log::debug("presence: no current key of {} to watch with",
                bazarish::log::redact(outgoing.peer));
            return;
        }
        const PresenceWatch watch{outgoing.id, outgoing.key, account.fingerprint, account.device,
            lane.runner->link->host(), utc};
        const Bytes frame = presenceWatchFrame(watch, identity.classical(), *epoch);
        if (outgoing.sentBefore) {
            sendAfterLookup(*lane.runner, outgoing.host, frame);
        } else {
            send(*lane.runner, outgoing.host, frame);
        }
        outgoing.sentBefore = true;
        outgoing.lastSent = now;
    }

    void sendRenew(WatcherLane& lane, Outgoing& outgoing, const Clock::time_point now)
    {
        send(*lane.runner, outgoing.host,
            sealedFrame(kRenewType, outgoing.id, outgoing.key, kToHolder, ++outgoing.sent,
                nlohmann::json::object()));
        outgoing.lastSent = now;
    }

    PresenceState stateFor(const Incoming& sub, const Clock::time_point now) const
    {
        // A live holder says online; offline is only its last word, so no renew races the tail.
        PresenceState state;
        state.online = shown;
        const auto typing = typingUntil.find(sub.peer);
        state.typing = state.online && typing != typingUntil.end() && typing->second > now;
        return state;
    }

    void tell(HolderLane& lane, Incoming& sub, const Clock::time_point now, const bool last)
    {
        const PresenceState state = last ? PresenceState{} : stateFor(sub, now);
        const nlohmann::json payload = {{"online", state.online}, {"typing", state.typing}};
        send(*lane.runner, sub.reply,
            sealedFrame(kStateType, sub.id, sub.key, kFromHolder, ++sub.sent, payload));
        sub.told = state;
    }

    void tellAllOffline(HolderLane& lane, const Clock::time_point now)
    {
        for (auto& [subscription, sub] : lane.incoming) {
            tell(lane, sub, now, true);
        }
    }

    void onWatch(const PresenceDay day, HolderLane& lane, const Bytes& frame,
        const Clock::time_point now)
    {
        const Bytes subscriptionId(frame.begin() + kTypeBytes, frame.begin() + kHeaderBytes);
        nlohmann::json content;
        try {
            content = parseCbor(
                ring->open(Bytes(frame.begin() + kHeaderBytes, frame.end())));
        } catch (const std::exception& error) {
            bazarish::log::debug("presence: a watch that does not open was dropped: {}", error.what());
            return;
        }
        if (content.value("t", std::string()) != kWatchTag
            || content.value("sub", std::string()) != toHex(subscriptionId)) {
            return;
        }
        const std::string from = content.value("from", std::string());
        const auto contact = contactFor(from);
        if (!contact.has_value() || !readsOn(from, day)) {
            return;
        }
        if (!content.contains(kWatchSignatureField) || !content.at(kWatchSignatureField).is_binary()) {
            return;
        }
        const Bytes signature = content.at(kWatchSignatureField).get_binary();
        content.erase(kWatchSignatureField);
        const auto device = contact->get().devices.find(content.value("dev", std::string()));
        if (device == contact->get().devices.end()
            || !verify(Key::fromPublicDer(device->second), watchSigningInput(content), signature)) {
            return;
        }
        const std::int64_t sentAt = content.value("sentAt", std::int64_t{0});
        const std::int64_t utc = timings.utcNow();
        if (sentAt < utc - kWatchSkewSeconds || sentAt > utc + kWatchSkewSeconds) {
            return;
        }
        Incoming sub;
        sub.peer = from;
        sub.reply = content.at("reply").get<std::string>();
        sub.id = subscriptionId;
        sub.key = fromBase64(content.at("key").get<std::string>());
        if (sub.key.size() != kSubscriptionKeyBytes) {
            return;
        }
        sub.expires = now + timings.subscriptionLife;
        Incoming& stored = lane.incoming[subscriptionOf(subscriptionId)] = std::move(sub);
        tell(lane, stored, now, false);
        if (const auto ours = watchers.find(day); ours != watchers.end()) {
            if (const auto outgoing = ours->second.peers.find(from);
                outgoing != ours->second.peers.end() && !outgoing->second.answered) {
                outgoing->second.lastSent = Clock::time_point{};
            }
        }
    }

    void onRenew(HolderLane& lane, const Bytes& frame, const Clock::time_point now)
    {
        const Bytes subscriptionId(frame.begin() + kTypeBytes, frame.begin() + kHeaderBytes);
        const auto found = lane.incoming.find(subscriptionOf(subscriptionId));
        if (found == lane.incoming.end()) {
            return;
        }
        Incoming& sub = found->second;
        if (!openedFrame(frame, sub.key, kToHolder, sub.heard)) {
            return;
        }
        sub.expires = now + timings.subscriptionLife;
        tell(lane, sub, now, false);
    }

    static void onState(WatcherLane& lane, const Bytes& frame, const Clock::time_point now)
    {
        const Bytes subscriptionId(frame.begin() + kTypeBytes, frame.begin() + kHeaderBytes);
        const auto found = std::find_if(lane.peers.begin(), lane.peers.end(),
            [&subscriptionId](const auto& entry) { return entry.second.id == subscriptionId; });
        if (found == lane.peers.end()) {
            return;
        }
        Outgoing& outgoing = found->second;
        const std::optional<nlohmann::json> payload
            = openedFrame(frame, outgoing.key, kFromHolder, outgoing.heard);
        if (!payload) {
            return;
        }
        outgoing.lastHeard = now;
        outgoing.carriedUntil = Clock::time_point{};
        outgoing.state = PresenceState{payload->value("online", false), payload->value("typing", false)};
        if (outgoing.state.online) {
            outgoing.answered = true;
            return;
        }
        rewatch(outgoing);
        outgoing.lastSent = now;
    }

    static void dropHolder(const PresenceDay day, HolderLane& lane, const std::string_view why)
    {
        bazarish::log::info(
            "presence: the presence address for {} is down: {}", presenceDayText(day), why);
        closeRunner(lane.runner);
        lane.incoming.clear();
        lane.readers.clear();
    }

    void raise(const PresenceDay day, HolderLane& lane, const Clock::time_point now)
    {
        PresenceLinkConfig config;
        config.keys = seed.destFor(day);
        config.readers = lane.wanted;
        try {
            lane.runner = openRunner(config, lane.inbox);
        } catch (const std::exception& error) {
            bazarish::log::info("presence: the presence address for {} did not come up: {}",
                presenceDayText(day), error.what());
            lane.raiseAfter = now + timings.watchRetry;
            return;
        }
        lane.readers = lane.wanted;
        bazarish::log::info("presence: the presence address for {} is up for {} readers",
            presenceDayText(day), lane.readers.size());
    }

    void retireDays(const std::vector<PresenceDay>& days, const Clock::time_point now)
    {
        const auto live = [&days](const PresenceDay day) {
            return std::find(days.begin(), days.end(), day) != days.end();
        };
        for (auto at = holders.begin(); at != holders.end();) {
            if (live(at->first)) {
                ++at;
                continue;
            }
            if (at->second.runner) {
                tellAllOffline(at->second, now);
                dropHolder(at->first, at->second, "its day is over");
            }
            at = holders.erase(at);
        }
        for (auto at = watchers.begin(); at != watchers.end();) {
            if (live(at->first)) {
                ++at;
                continue;
            }
            closeRunner(at->second.runner);
            at = watchers.erase(at);
        }
    }

    void takeContacts(const std::vector<PresenceDay>& days, const bool changed,
        const Clock::time_point now)
    {
        for (const PresenceDay day : days) {
            const auto [at, added] = holders.try_emplace(day);
            if (!added && !changed) {
                continue;
            }
            HolderLane& lane = at->second;
            std::vector<Bytes> readers = readersWanted(day);
            if (!sameReaders(readers, lane.wanted)) {
                lane.wanted = std::move(readers);
                lane.readersChanged = now;
            }
            std::erase_if(lane.incoming,
                [this, day](const auto& entry) { return !readsOn(entry.second.peer, day); });
        }
    }

    bool active() const
    {
        return focused && shown && !away;
    }

    std::string_view holderEnd(const Clock::time_point now) const
    {
        if (!shown) {
            return "the status is hidden";
        }
        if (away) {
            return "the device went away";
        }
        if (now - lastOnline >= timings.onlineTail) {
            return "the online tail ran out";
        }
        return {};
    }

    void tickHolders(const Clock::time_point now)
    {
        const bool online = active();
        if (online) {
            lastOnline = now;
        }
        const std::string_view ended = holderEnd(now);
        for (auto& [day, lane] : holders) {
            if (lane.runner) {
                std::erase_if(lane.incoming, [now](const auto& entry) { return entry.second.expires <= now; });
                if (!ended.empty()) {
                    tellAllOffline(lane, now);
                    dropHolder(day, lane, ended);
                    continue;
                }
                if (!sameReaders(lane.wanted, lane.readers)
                    && now - lane.readersChanged >= timings.readersSettle) {
                    tellAllOffline(lane, now);
                    dropHolder(day, lane, "the readers changed");
                }
            }
            if (!lane.runner) {
                if (online && !lane.wanted.empty() && now >= lane.raiseAfter
                    && i2p::transportState() == i2p::TransportState::eUp) {
                    raise(day, lane, now);
                }
                continue;
            }
            for (auto& [subscription, sub] : lane.incoming) {
                if (sub.told != stateFor(sub, now)) {
                    tell(lane, sub, now, false);
                }
            }
        }
    }

    void dropWatcher(const PresenceDay day, WatcherLane& lane, const Clock::time_point now)
    {
        bazarish::log::info(
            "presence: the watching address for {} was taken down", presenceDayText(day));
        closeRunner(lane.runner);
        for (auto& [peerFp, outgoing] : lane.peers) {
            carry(outgoing, now);
            rewatch(outgoing);
            outgoing.sentBefore = false;
            outgoing.lastSent = Clock::time_point{};
        }
    }

    void tickPeers(const Clock::time_point now)
    {
        // A watch names its sender, so a device that hides its own status watches no one.
        const bool watchingAny = active();
        for (auto& [day, lane] : watchers) {
            std::erase_if(lane.peers, [&, day = day](const auto& entry) {
                const auto contact = contactFor(entry.first);
                return !watchingAny || !contact.has_value() || !watching(entry.first)
                    || !scheduledOn(contact->get().schedule, day).has_value();
            });
        }
        if (!watchingAny) {
            return;
        }
        for (auto& [day, lane] : watchers) {
            if (!lane.runner) {
                continue;
            }
            for (const std::string& peerFp : watched) {
                const auto contact = contactFor(peerFp);
                if (!contact.has_value()) {
                    continue;
                }
                const std::optional<ScheduledDay> scheduled = scheduledOn(contact->get().schedule, day);
                if (!scheduled.has_value()) {
                    continue;
                }
                auto found = lane.peers.find(peerFp);
                if (found == lane.peers.end()) {
                    found = lane.peers.emplace(peerFp, outgoingTo(contact->get(), scheduled->dest)).first;
                }
                tickPeer(lane, found->second, now);
            }
        }
    }

    void tickPeer(WatcherLane& lane, Outgoing& outgoing, const Clock::time_point now)
    {
        const bool renewUnanswered = outgoing.answered && outgoing.lastSent > outgoing.lastHeard
            && now - outgoing.lastSent >= timings.watchRetry;
        if (renewUnanswered) {
            carry(outgoing, now);
            rewatch(outgoing);
            outgoing.lastSent = Clock::time_point{};
        }
        if (outgoing.answered) {
            if (now - outgoing.lastSent >= timings.renewEvery) {
                sendRenew(lane, outgoing, now);
            }
            return;
        }
        if (outgoing.carriedUntil != Clock::time_point{} && now >= outgoing.carriedUntil) {
            outgoing.state = PresenceState{};
            outgoing.carriedUntil = Clock::time_point{};
        }
        if (now - outgoing.lastSent >= timings.watchRetry) {
            sendWatch(lane, outgoing, now);
        }
    }

    void openWatchers(const std::vector<PresenceDay>& days)
    {
        if (!active() || i2p::transportState() != i2p::TransportState::eUp) {
            return;
        }
        for (const PresenceDay day : days) {
            WatcherLane& lane = watchers[day];
            if (lane.runner) {
                continue;
            }
            PresenceLinkConfig config;
            config.readerKey = seed.readerFor(day).rawPrivate();
            try {
                lane.runner = openRunner(config, lane.inbox);
            } catch (const std::exception& error) {
                bazarish::log::info("presence: the watching address for {} did not come up: {}",
                    presenceDayText(day), error.what());
            }
            OPENSSL_cleanse(config.readerKey.data(), config.readerKey.size());
        }
    }

    void closeWatchers()
    {
        for (auto& [day, lane] : watchers) {
            closeRunner(lane.runner);
        }
        watchers.clear();
    }

    PresenceState stateOf(const std::string& peerFp) const
    {
        PresenceState state;
        for (const auto& [day, lane] : watchers) {
            if (const auto found = lane.peers.find(peerFp); found != lane.peers.end()) {
                state.online = state.online || found->second.state.online;
                state.typing = state.typing || found->second.state.typing;
            }
        }
        return state;
    }

    void tellChanges()
    {
        std::set<std::string> peers;
        for (const auto& [peerFp, state] : shownStates) {
            peers.insert(peerFp);
        }
        for (const auto& [day, lane] : watchers) {
            for (const auto& [peerFp, outgoing] : lane.peers) {
                peers.insert(peerFp);
            }
        }
        for (const std::string& peerFp : peers) {
            const PresenceState state = stateOf(peerFp);
            const auto held = shownStates.find(peerFp);
            const PresenceState before = held == shownStates.end() ? PresenceState{} : held->second;
            if (state == before) {
                continue;
            }
            sink(peerFp, state);
            if (state == PresenceState{}) {
                shownStates.erase(peerFp);
            } else {
                shownStates[peerFp] = state;
            }
        }
    }

    static void takeFrame(const std::string_view kind, const std::function<void()>& take)
    {
        try {
            take();
        } catch (const std::exception& error) {
            bazarish::log::info("presence: a {} frame that does not read was dropped: {}", kind,
                error.what());
        }
    }

    void run()
    {
        while (true) {
            std::map<PresenceDay, std::deque<Bytes>> holderFrames;
            std::map<PresenceDay, std::deque<Bytes>> watcherFrames;
            bool contactsChanged = false;
            std::uint64_t leaveAsked = 0;
            {
                std::unique_lock<std::mutex> lock(mutex);
                wake.wait_for(lock, timings.tick);
                if (stopping) {
                    break;
                }
                focused = inputs.focused;
                away = inputs.away;
                leaveAsked = inputs.leaveAsked;
                shown = inputs.shown;
                watched = inputs.watched;
                typingUntil = inputs.typingUntil;
                if (inputs.contactsVersion != contactsVersion) {
                    contacts = inputs.contacts;
                    contactsVersion = inputs.contactsVersion;
                    contactsChanged = true;
                }
                for (auto& [day, lane] : holders) {
                    holderFrames[day].swap(lane.inbox);
                }
                for (auto& [day, lane] : watchers) {
                    watcherFrames[day].swap(lane.inbox);
                }
            }
            const Clock::time_point now = Clock::now();
            std::erase_if(typingUntil, [now](const auto& entry) { return entry.second <= now; });
            const std::vector<PresenceDay> days = liveDays(timings.utcNow());
            retireDays(days, now);
            takeContacts(days, contactsChanged, now);
            for (auto& [day, lane] : holders) {
                if (lane.runner && lane.runner->link->lost()) {
                    dropHolder(day, lane, "the transport took it down");
                }
            }
            for (const auto& [day, frames] : holderFrames) {
                const auto lane = holders.find(day);
                for (const Bytes& frame : frames) {
                    if (lane == holders.end() || !lane->second.runner || frame.size() <= kHeaderBytes) {
                        continue;
                    }
                    if (frame[0] == kWatchType) {
                        takeFrame("watch", [&]() { onWatch(day, lane->second, frame, now); });
                    } else if (frame[0] == kRenewType) {
                        takeFrame("renew", [&]() { onRenew(lane->second, frame, now); });
                    }
                }
            }
            for (const auto& [day, frames] : watcherFrames) {
                const auto lane = watchers.find(day);
                for (const Bytes& frame : frames) {
                    if (lane != watchers.end() && frame.size() > kHeaderBytes
                        && frame[0] == kStateType) {
                        takeFrame("state", [&]() { onState(lane->second, frame, now); });
                    }
                }
            }
            for (auto& [day, lane] : watchers) {
                if (lane.runner && lane.runner->link->lost()) {
                    dropWatcher(day, lane, now);
                }
            }
            openWatchers(days);
            tickHolders(now);
            tickPeers(now);
            if (!active()) {
                closeWatchers();
            }
            tellChanges();
            if (leaveAsked != leftThrough) {
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    leftThrough = leaveAsked;
                }
                left.notify_all();
            }
        }
        closeWatchers();
        for (auto& [day, lane] : holders) {
            closeRunner(lane.runner);
        }
    }
};


Presence::Presence(PresenceAccount account, PresenceNet net, PresenceSink sink,
    const PresenceTimings timings)
    : impl_(std::make_unique<Impl>(std::move(account), std::move(net), std::move(sink), timings))
{
}

Presence::~Presence() = default;

void Presence::setFocused(const bool focused)
{
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->inputs.focused = focused;
    }
    impl_->wake.notify_all();
}

void Presence::setAway(const bool away)
{
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->inputs.away = away;
    }
    impl_->wake.notify_all();
}

void Presence::leave()
{
    std::unique_lock<std::mutex> lock(impl_->mutex);
    impl_->inputs.away = true;
    const std::uint64_t asked = ++impl_->inputs.leaveAsked;
    impl_->wake.notify_all();
    impl_->left.wait(lock, [this, asked]() { return impl_->leftThrough >= asked; });
}

void Presence::setShown(const bool shown)
{
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->inputs.shown = shown;
        setPresenceWanted(impl_->id, shown);
    }
    impl_->wake.notify_all();
}

void Presence::setContacts(std::vector<PresenceContact> ordered)
{
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->inputs.contacts = std::move(ordered);
        ++impl_->inputs.contactsVersion;
    }
    impl_->wake.notify_all();
}

void Presence::watch(std::vector<std::string> peers)
{
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->inputs.watched = std::move(peers);
    }
    impl_->wake.notify_all();
}

void Presence::stoppedTyping(const std::string& peer)
{
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->inputs.typingUntil.erase(peer);
    }
    impl_->wake.notify_all();
}

void Presence::typed(const std::string& peer)
{
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        const Clock::time_point now = Clock::now();
        std::erase_if(impl_->inputs.typingUntil,
            [now](const auto& entry) { return entry.second <= now; });
        impl_->inputs.typingUntil[peer] = now + impl_->timings.typingPulse;
    }
    impl_->wake.notify_all();
}

}  // namespace bazarish::client
