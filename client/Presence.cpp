// Bazarish project (c) 2026
#include "Presence.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
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
constexpr int kPresenceTunnelQuantity = 2;

std::int64_t unixNow()
{
    return std::chrono::duration_cast<seconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

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
    return nlohmann::json::from_cbor(*plain);
}

class I2pPresenceLink final : public PresenceLink {
public:
    explicit I2pPresenceLink(std::shared_ptr<i2p::Endpoint> endpoint)
        : endpoint_(std::move(endpoint))
    {
    }

    ~I2pPresenceLink() override
    {
        endpoint_->stop();
    }

    std::string host() const override
    {
        return endpoint_->routingHost();
    }

    void send(const std::string& host, const Bytes& datagram) override
    {
        endpoint_->sendRawDatagram(host, datagram.data(), datagram.size());
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
    std::shared_ptr<i2p::Endpoint> endpoint_;
};

struct Outgoing {
    std::string peer;
    std::string host;
    Bytes sealingKeyDer;
    Bytes id;
    Bytes key;
    std::uint64_t sent = 0;
    std::uint64_t heard = 0;
    bool answered = false;
    Clock::time_point lastSent{};
    Clock::time_point lastHeard{};
    Clock::time_point started{};
    Clock::duration patience{};
    PresenceState state;
    std::string holderDevice;
};

struct Incoming {
    std::string peer;
    std::string reply;
    Bytes id;
    Bytes key;
    std::uint64_t sent = 0;
    std::uint64_t heard = 0;
    Clock::time_point expires{};
    bool sibling = false;
    bool focused = false;
    std::map<std::string, Clock::time_point> typingUntil;
    std::optional<PresenceState> told;
};

enum class Role { eNone, eProbing, eSibling, eHolder };

}  // namespace

Bytes presenceWatchFrame(const PresenceWatch& watch, const Key& signer, const Key& recipientSealing)
{
    nlohmann::json content = {
        {"t", kWatchTag},
        {"from", watch.from},
        {"device", watch.device},
        {"reply", watch.reply},
        {"sub", toHex(watch.id)},
        {"key", toBase64(watch.key)},
        {"sentAt", watch.sentAt},
    };
    content[kWatchSignatureField] = nlohmann::json::binary(sign(signer, watchSigningInput(content)));
    const Bytes sealed = hybrid::seal(nlohmann::json::to_cbor(content), recipientSealing);
    Bytes frame = headerFor(kWatchType, watch.id);
    frame.insert(frame.end(), sealed.begin(), sealed.end());
    return frame;
}

PresenceNet i2pPresenceNet(std::filesystem::path routerDir, std::string owner)
{
    return [routerDir = std::move(routerDir), owner = std::move(owner)](
               const PresenceLinkConfig& config) -> std::unique_ptr<PresenceLink> {
        i2p::EndpointConfig endpoint;
        endpoint.keys = config.keys;
        endpoint.privacy = tunnelPrivacy();
        endpoint.tunnelQuantity = kPresenceTunnelQuantity;
        endpoint.published = true;
        endpoint.label = "Presence";
        endpoint.owner = owner;
        endpoint.traffic = i2p::Traffic::eRaw;
        endpoint.leaseSetReaders = config.readers;
        endpoint.leaseSetReaderKey = config.readerKey;
        return std::make_unique<I2pPresenceLink>(
            sharedI2pRouter(routerDir).createEndpoint(endpoint));
    };
}

struct Presence::Impl {
    struct Runner {
        std::unique_ptr<PresenceLink> link;
        std::thread reader;
        std::atomic<bool> stopping{false};
    };

    PresenceAccount account;
    PresenceTimings timings;
    Identity identity;
    Key sealingKey;
    PresenceNet net;
    PresenceSink sink;

    std::mutex mutex;
    std::condition_variable wake;
    bool stopping = false;
    struct Inputs {
        bool focused = false;
        bool shown = true;
        std::vector<PresenceContact> contacts;
        std::uint64_t contactsVersion = 0;
        std::vector<std::string> watched;
        std::map<std::string, Clock::time_point> typingUntil;
        std::deque<Bytes> holderInbox;
        std::deque<Bytes> watcherInbox;
    } inputs;

    bool focused = false;
    bool shown = true;
    std::vector<PresenceContact> contacts;
    std::uint64_t contactsVersion = 0;
    std::vector<std::string> watched;
    std::map<std::string, Clock::time_point> typingUntil;
    std::vector<std::pair<std::string, PresenceState>> told;

    std::unique_ptr<Runner> watcher;
    std::unique_ptr<Runner> holder;
    std::vector<Bytes> holderReaders;
    std::vector<Bytes> wantedReaders;
    bool readersStale = true;
    Clock::time_point readersChanged{};
    Role role = Role::eNone;
    std::optional<Outgoing> own;
    std::map<std::string, Outgoing> peers;
    std::map<std::uint64_t, Incoming> incoming;
    Clock::time_point lastOnline{};
    Clock::time_point lastSelfCheck{};
    Clock::time_point lastTypingRenew{};
    std::thread worker;

    Impl(PresenceAccount accountIn, PresenceNet netIn, PresenceSink sinkIn,
        const PresenceTimings timingsIn)
        : account(std::move(accountIn))
        , timings(timingsIn)
        , identity(Identity::fromPrivatePem(account.identityPem))
        , sealingKey(Key::fromPrivatePem(account.sealingPem))
        , net(std::move(netIn))
        , sink(std::move(sinkIn))
    {
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
    }

    std::unique_ptr<Runner> openRunner(const PresenceLinkConfig& config, std::deque<Bytes>& inbox)
    {
        auto runner = std::make_unique<Runner>();
        runner->link = net(config);
        Runner* const raw = runner.get();
        runner->reader = std::thread([this, raw, &inbox]() {
            while (!raw->stopping.load()) {
                std::optional<Bytes> got = raw->link->receive(kReceiveSlice);
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

    const PresenceContact* contactFor(const std::string& fingerprint, const bool readersOnly) const
    {
        const std::size_t limit = readersOnly ? kMaxPresenceReaders : contacts.size();
        for (std::size_t index = 0; index < contacts.size() && index < limit; ++index) {
            if (contacts[index].fingerprint == fingerprint) {
                return &contacts[index];
            }
        }
        return nullptr;
    }

    std::vector<Bytes> readersWanted() const
    {
        std::vector<Bytes> readers{Key::fromPublicDer(account.presenceKeyDer).rawPublic()};
        for (std::size_t index = 0; index < contacts.size() && index < kMaxPresenceReaders;
             ++index) {
            readers.push_back(Key::fromPublicDer(contacts[index].presenceKeyDer).rawPublic());
        }
        return readers;
    }

    void send(Runner& runner, const std::string& host, const Bytes& datagram)
    {
        try {
            runner.link->send(host, datagram);
        } catch (const std::exception& error) {
            bazarish::log::info("presence: a datagram was not sent: {}", error.what());
        }
    }

    Outgoing outgoingTo(const std::string& peerFp, const std::string& host,
        const Bytes& sealingKeyDer, const Clock::time_point now)
    {
        Outgoing outgoing;
        outgoing.peer = peerFp;
        outgoing.host = host;
        outgoing.sealingKeyDer = sealingKeyDer;
        outgoing.id = randomBytes(kPresenceSubscriptionIdBytes);
        outgoing.key = randomBytes(kSubscriptionKeyBytes);
        outgoing.started = now;
        const Bytes spread = randomBytes(1);
        outgoing.patience = timings.probeDeadline
            + timings.probeDeadline * spread[0] / (2 * std::numeric_limits<std::uint8_t>::max());
        return outgoing;
    }

    void sendWatch(Outgoing& outgoing, const Clock::time_point now)
    {
        const PresenceWatch watch{outgoing.id, outgoing.key, account.fingerprint, account.device,
            watcher->link->host(), unixNow()};
        send(*watcher, outgoing.host,
            presenceWatchFrame(watch, identity.classical(), Key::fromPublicDer(outgoing.sealingKeyDer)));
        outgoing.lastSent = now;
    }

    void sendRenew(Outgoing& outgoing, const nlohmann::json& payload, const Clock::time_point now)
    {
        send(*watcher, outgoing.host,
            sealedFrame(kRenewType, outgoing.id, outgoing.key, kToHolder, ++outgoing.sent, payload));
        outgoing.lastSent = now;
    }

    nlohmann::json typingList(const Clock::time_point now) const
    {
        nlohmann::json list = nlohmann::json::array();
        for (const auto& [peerFp, until] : typingUntil) {
            if (until > now) {
                list.push_back(peerFp);
            }
        }
        return list;
    }

    bool rawOnline(const Clock::time_point now) const
    {
        if (focused && shown) {
            return true;
        }
        for (const auto& [id, sub] : incoming) {
            if (sub.sibling && sub.focused && sub.expires > now) {
                return true;
            }
        }
        return false;
    }

    PresenceState stateFor(const Incoming& sub, const Clock::time_point now) const
    {
        PresenceState state;
        state.online = now - lastOnline < timings.onlineTail;
        if (sub.sibling) {
            return state;
        }
        const auto own = typingUntil.find(sub.peer);
        state.typing = own != typingUntil.end() && own->second > now;
        for (const auto& [id, other] : incoming) {
            if (!other.sibling || other.expires <= now) {
                continue;
            }
            const auto theirs = other.typingUntil.find(sub.peer);
            state.typing = state.typing || (theirs != other.typingUntil.end() && theirs->second > now);
        }
        state.typing = state.typing && state.online;
        return state;
    }

    void tell(Incoming& sub, const Clock::time_point now)
    {
        const PresenceState state = stateFor(sub, now);
        nlohmann::json payload = {{"online", state.online}, {"typing", state.typing}};
        if (sub.peer == account.fingerprint) {
            payload["device"] = account.device;
        }
        send(*holder, sub.reply,
            sealedFrame(kStateType, sub.id, sub.key, kFromHolder, ++sub.sent, payload));
        sub.told = state;
    }

    void onWatch(const Bytes& frame, const Clock::time_point now)
    {
        const Bytes id(frame.begin() + kTypeBytes, frame.begin() + kHeaderBytes);
        nlohmann::json content;
        try {
            content = nlohmann::json::from_cbor(
                hybrid::unseal(Bytes(frame.begin() + kHeaderBytes, frame.end()), sealingKey));
        } catch (const std::exception&) {
            return;
        }
        if (content.value("t", std::string()) != kWatchTag
            || content.value("sub", std::string()) != toHex(id)) {
            return;
        }
        const std::string from = content.value("from", std::string());
        IdentityKeys known;
        if (from == account.fingerprint) {
            known = account.identity;
        } else if (const PresenceContact* contact = contactFor(from, true); contact != nullptr) {
            known = contact->identity;
        } else {
            return;
        }
        if (!content.contains(kWatchSignatureField) || !content.at(kWatchSignatureField).is_binary()) {
            return;
        }
        const Bytes signature = content.at(kWatchSignatureField).get_binary();
        content.erase(kWatchSignatureField);
        if (!verify(Key::fromPublicDer(known.classicalDer), watchSigningInput(content), signature)) {
            return;
        }
        const std::int64_t sentAt = content.value("sentAt", std::int64_t{0});
        if (sentAt < unixNow() - kWatchSkewSeconds || sentAt > unixNow() + kWatchSkewSeconds) {
            return;
        }
        Incoming sub;
        sub.peer = from;
        sub.reply = content.at("reply").get<std::string>();
        sub.id = id;
        sub.key = fromBase64(content.at("key").get<std::string>());
        if (sub.key.size() != kSubscriptionKeyBytes) {
            return;
        }
        sub.sibling = from == account.fingerprint
            && content.value("device", std::string()) != account.device;
        sub.expires = now + timings.subscriptionLife;
        Incoming& stored = incoming[subscriptionOf(id)] = std::move(sub);
        tell(stored, now);
    }

    void onRenew(const Bytes& frame, const Clock::time_point now)
    {
        const Bytes id(frame.begin() + kTypeBytes, frame.begin() + kHeaderBytes);
        const auto found = incoming.find(subscriptionOf(id));
        if (found == incoming.end()) {
            return;
        }
        Incoming& sub = found->second;
        const std::optional<nlohmann::json> payload = openedFrame(frame, sub.key, kToHolder, sub.heard);
        if (!payload) {
            return;
        }
        sub.expires = now + timings.subscriptionLife;
        if (sub.sibling) {
            sub.focused = payload->value("focused", false);
            for (const nlohmann::json& typing : payload->value("typing", nlohmann::json::array())) {
                sub.typingUntil[typing.get<std::string>()] = now + timings.typingPulse;
            }
        }
        tell(sub, now);
    }

    void onState(const Bytes& frame, const Clock::time_point now)
    {
        const Bytes id(frame.begin() + kTypeBytes, frame.begin() + kHeaderBytes);
        Outgoing* outgoing = own && own->id == id ? &*own : nullptr;
        for (auto& [peerFp, watching] : peers) {
            if (outgoing == nullptr && watching.id == id) {
                outgoing = &watching;
            }
        }
        if (outgoing == nullptr) {
            return;
        }
        const std::optional<nlohmann::json> payload
            = openedFrame(frame, outgoing->key, kFromHolder, outgoing->heard);
        if (!payload) {
            return;
        }
        outgoing->answered = true;
        outgoing->lastHeard = now;
        outgoing->holderDevice = payload->value("device", std::string());
        const PresenceState state{payload->value("online", false), payload->value("typing", false)};
        const bool fromOwnAddress = own && outgoing == &*own;
        if (!fromOwnAddress && state != outgoing->state) {
            told.emplace_back(outgoing->peer, state);
        }
        outgoing->state = state;
    }

    void becomeHolder(const Clock::time_point now)
    {
        closeRunner(holder);
        PresenceLinkConfig config;
        config.keys = i2p::Keys::fromBlob(account.destKeys);
        config.readers = readersWanted();
        try {
            holder = openRunner(config, inputs.holderInbox);
        } catch (const std::exception& error) {
            bazarish::log::info("presence: the presence address did not come up: {}", error.what());
            role = Role::eNone;
            own.reset();
            return;
        }
        holderReaders = config.readers;
        wantedReaders = config.readers;
        role = Role::eHolder;
        own.reset();
        lastSelfCheck = now;
    }

    void dropHolder()
    {
        closeRunner(holder);
        incoming.clear();
        holderReaders.clear();
    }

    void tickOwn(const Clock::time_point now)
    {
        if (!shown) {
            dropHolder();
            own.reset();
            role = Role::eNone;
            return;
        }
        if (rawOnline(now)) {
            lastOnline = now;
        }
        if (role == Role::eHolder) {
            std::erase_if(incoming, [now](const auto& entry) { return entry.second.expires <= now; });
            if (now - lastOnline >= timings.onlineTail) {
                for (auto& [id, sub] : incoming) {
                    tell(sub, now);
                }
                dropHolder();
                role = Role::eNone;
                return;
            }
            for (auto& [id, sub] : incoming) {
                if (sub.told != stateFor(sub, now)) {
                    tell(sub, now);
                }
            }
            if (wantedReaders != holderReaders && now - readersChanged >= timings.readersSettle) {
                becomeHolder(now);
                return;
            }
            if (focused && watcher && now - lastSelfCheck >= timings.selfCheckEvery) {
                own = outgoingTo(account.fingerprint, account.dest, sealingKey.publicDer(), now);
                sendWatch(*own, now);
                lastSelfCheck = now;
            }
            if (own && own->answered && !own->holderDevice.empty()
                && own->holderDevice != account.device) {
                dropHolder();
                role = Role::eSibling;
                own->lastHeard = now;
            }
            return;
        }
        if (!focused) {
            if (role == Role::eSibling && own && watcher) {
                sendRenew(*own, {{"focused", false}, {"typing", nlohmann::json::array()}}, now);
            }
            own.reset();
            role = Role::eNone;
            return;
        }
        if (!watcher) {
            return;
        }
        if (role == Role::eNone) {
            own = outgoingTo(account.fingerprint, account.dest, sealingKey.publicDer(), now);
            sendWatch(*own, now);
            role = Role::eProbing;
            return;
        }
        if (role == Role::eProbing) {
            if (own->answered) {
                role = Role::eSibling;
                return;
            }
            if (now - own->started >= own->patience) {
                becomeHolder(now);
                return;
            }
            if (now - own->lastSent >= timings.watchRetry) {
                sendWatch(*own, now);
            }
            return;
        }
        if (now - own->lastHeard >= timings.holderSilence) {
            becomeHolder(now);
            return;
        }
        const nlohmann::json typing = typingList(now);
        const bool typingNow = !typing.empty() && now - lastTypingRenew >= timings.typingResend;
        if (typingNow || now - own->lastSent >= timings.siblingKeepalive) {
            sendRenew(*own, {{"focused", true}, {"typing", typing}}, now);
            if (typingNow) {
                lastTypingRenew = now;
            }
        }
    }

    void tickPeers(const Clock::time_point now)
    {
        for (auto at = peers.begin(); at != peers.end();) {
            const bool still = focused && contactFor(at->first, false) != nullptr
                && std::find(watched.begin(), watched.end(), at->first) != watched.end();
            if (still) {
                ++at;
                continue;
            }
            told.emplace_back(at->first, PresenceState{});
            at = peers.erase(at);
        }
        if (!focused || !watcher) {
            return;
        }
        for (const std::string& peerFp : watched) {
            const PresenceContact* contact = contactFor(peerFp, false);
            if (contact == nullptr) {
                continue;
            }
            const auto found = peers.find(peerFp);
            if (found == peers.end()) {
                Outgoing& started = peers[peerFp]
                    = outgoingTo(peerFp, contact->presenceDest, contact->sealingKeyDer, now);
                sendWatch(started, now);
                continue;
            }
            tickPeer(found->second, *contact, now);
        }
    }

    void tickPeer(Outgoing& outgoing, const PresenceContact& contact, const Clock::time_point now)
    {
        if (!outgoing.answered) {
            const milliseconds retry = now - outgoing.started < timings.probeDeadline
                ? timings.watchRetry
                : timings.renewEvery;
            if (now - outgoing.lastSent >= retry) {
                sendWatch(outgoing, now);
            }
            return;
        }
        if (now - outgoing.lastHeard >= timings.subscriptionLife) {
            if (outgoing.state != PresenceState{}) {
                told.emplace_back(outgoing.peer, PresenceState{});
            }
            outgoing = outgoingTo(contact.fingerprint, contact.presenceDest, contact.sealingKeyDer, now);
            sendWatch(outgoing, now);
            return;
        }
        if (now - outgoing.lastSent >= timings.renewEvery) {
            sendRenew(outgoing, nlohmann::json::object(), now);
        }
    }

    void openWatcher()
    {
        if (!focused || watcher) {
            return;
        }
        PresenceLinkConfig config;
        config.readerKey = account.readerKey;
        try {
            watcher = openRunner(config, inputs.watcherInbox);
        } catch (const std::exception& error) {
            bazarish::log::info("presence: the watching address did not come up: {}", error.what());
        }
    }

    void run()
    {
        while (true) {
            std::deque<Bytes> holderFrames;
            std::deque<Bytes> watcherFrames;
            {
                std::unique_lock<std::mutex> lock(mutex);
                wake.wait_for(lock, timings.tick);
                if (stopping) {
                    break;
                }
                focused = inputs.focused;
                shown = inputs.shown;
                watched = inputs.watched;
                typingUntil = inputs.typingUntil;
                if (inputs.contactsVersion != contactsVersion) {
                    contacts = inputs.contacts;
                    contactsVersion = inputs.contactsVersion;
                    readersStale = true;
                }
                holderFrames.swap(inputs.holderInbox);
                watcherFrames.swap(inputs.watcherInbox);
            }
            const Clock::time_point now = Clock::now();
            std::erase_if(typingUntil, [now](const auto& entry) { return entry.second <= now; });
            if (readersStale) {
                if (std::vector<Bytes> readers = readersWanted(); readers != wantedReaders) {
                    wantedReaders = std::move(readers);
                    readersChanged = now;
                }
                readersStale = false;
            }
            openWatcher();
            for (const Bytes& frame : holderFrames) {
                if (role != Role::eHolder || frame.size() <= kHeaderBytes) {
                    continue;
                }
                if (frame[0] == kWatchType) {
                    onWatch(frame, now);
                } else if (frame[0] == kRenewType) {
                    onRenew(frame, now);
                }
            }
            for (const Bytes& frame : watcherFrames) {
                if (frame.size() > kHeaderBytes && frame[0] == kStateType) {
                    onState(frame, now);
                }
            }
            tickOwn(now);
            tickPeers(now);
            if (!focused) {
                closeRunner(watcher);
            }
            for (const auto& [peerFp, state] : told) {
                sink(peerFp, state);
            }
            told.clear();
        }
        closeRunner(watcher);
        closeRunner(holder);
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

void Presence::setShown(const bool shown)
{
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->inputs.shown = shown;
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
