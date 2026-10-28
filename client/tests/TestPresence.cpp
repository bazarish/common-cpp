// Bazarish project (c) 2026
#include "I2pKeys.hpp"
#include "Presence.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include "TestUtil.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;
using std::chrono::milliseconds;

namespace {

constexpr milliseconds kSettle{6000};
constexpr milliseconds kPoll{20};
constexpr std::size_t kCrowdBeyondCap = 50;
constexpr milliseconds kKnockWait{1500};
constexpr milliseconds kTypeEvery{100};
constexpr int kTypingRounds = 10;
constexpr milliseconds kSlowRetry{5000};
constexpr milliseconds kWakeWithin{1500};
constexpr milliseconds kUnanswered{300};
constexpr milliseconds kPublishDelay{300};
constexpr milliseconds kQuietWatch{4000};
constexpr milliseconds kLongSilence{20000};
constexpr milliseconds kStaleRetry{600};
constexpr milliseconds kShortTail{300};
constexpr milliseconds kAwayBeforeReturn{1000};

PresenceTimings fastTimings()
{
    PresenceTimings timings;
    timings.watchRetry = milliseconds(100);
    timings.renewEvery = milliseconds(300);
    timings.subscriptionLife = milliseconds(900);
    timings.onlineTail = milliseconds(800);
    timings.typingPulse = milliseconds(500);
    timings.readersSettle = milliseconds(200);
    timings.tick = milliseconds(20);
    return timings;
}

class FakeNet {
public:
    struct Box {
        std::string host;
        std::vector<Bytes> readers;
        Bytes readerPublic;
        std::uint64_t generation = 0;
        std::chrono::steady_clock::time_point publishedAt{};
        std::atomic<bool> lost{false};
        std::mutex mutex;
        std::condition_variable arrived;
        std::deque<Bytes> queue;
    };

    void knowReader(const Key& key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        publicOf_[toHex(key.rawPrivate())] = key.rawPublic();
    }

    std::shared_ptr<Box> open(const PresenceLinkConfig& config)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto box = std::make_shared<Box>();
        box->host = config.keys.has_value() ? i2pRoutingHost(config.keys->blob())
                                            : "watcher" + std::to_string(++opened_) + ".b32.i2p";
        box->readers = config.readers;
        if (!config.readerKey.empty()) {
            box->readerPublic = publicOf_.at(toHex(config.readerKey));
        }
        box->generation = ++opened_;
        box->publishedAt = std::chrono::steady_clock::now()
            + (config.keys.has_value() ? kPublishDelay : milliseconds::zero());
        live_.push_back(box);
        published_.push_back(box);
        return box;
    }

    void close(const std::shared_ptr<Box>& box)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::erase(live_, box);
    }

    // The netdb answers with the newest lease set published, the holder alive or not, and a
    // sender keeps what it found, as libi2pd does, until it looks again from a new destination.
    void send(const Box& from, const std::string& host, const Bytes& datagram)
    {
        std::shared_ptr<Box> target;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const std::pair<std::uint64_t, std::string> route{from.generation, host};
            if (const auto known = resolved_.find(route); known != resolved_.end()) {
                target = known->second;
            } else {
                const auto now = std::chrono::steady_clock::now();
                for (const std::shared_ptr<Box>& box : published_) {
                    if (box->host == host && box->publishedAt <= now && readable(*box, from)
                        && (!target || box->generation > target->generation)) {
                        target = box;
                    }
                }
                if (!target) {
                    return;
                }
                resolved_[route] = target;
            }
            const bool gone = std::find(live_.begin(), live_.end(), target) == live_.end();
            if (gone || target->lost.load()) {
                return;
            }
        }
        {
            std::lock_guard<std::mutex> lock(target->mutex);
            target->queue.push_back(datagram);
        }
        target->arrived.notify_all();
    }

    static bool readable(const Box& leaseSet, const Box& reader)
    {
        return leaseSet.readers.empty()
            || std::find(leaseSet.readers.begin(), leaseSet.readers.end(), reader.readerPublic)
            != leaseSet.readers.end();
    }

    void lose(const std::string& host)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const std::shared_ptr<Box>& box : live_) {
            if (box->host == host) {
                box->lost.store(true);
            }
        }
    }

    std::uint64_t newestGeneration(const std::string& host)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::uint64_t newest = 0;
        for (const std::shared_ptr<Box>& box : live_) {
            if (box->host == host && !box->lost.load()) {
                newest = std::max(newest, box->generation);
            }
        }
        return newest;
    }

    std::size_t readersOf(const std::string& host)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::shared_ptr<Box> newest;
        for (const std::shared_ptr<Box>& box : live_) {
            if (box->host == host && (!newest || box->generation > newest->generation)) {
                newest = box;
            }
        }
        return newest ? newest->readers.size() : 0;
    }

    std::size_t watchersOf(const Key& presence)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<std::size_t>(std::count_if(published_.begin(), published_.end(),
            [&presence](const std::shared_ptr<Box>& box) {
                return box->readerPublic == presence.rawPublic();
            }));
    }

    int holdersOf(const std::string& host)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<int>(std::count_if(live_.begin(), live_.end(),
            [&host](const std::shared_ptr<Box>& box) { return box->host == host; }));
    }

private:
    std::mutex mutex_;
    std::map<std::string, Bytes> publicOf_;
    std::vector<std::shared_ptr<Box>> live_;
    std::vector<std::shared_ptr<Box>> published_;
    std::map<std::pair<std::uint64_t, std::string>, std::shared_ptr<Box>> resolved_;
    std::uint64_t opened_ = 0;
};

class FakeLink final : public PresenceLink {
public:
    FakeLink(FakeNet& net, std::shared_ptr<FakeNet::Box> box)
        : net_(net)
        , box_(std::move(box))
    {
    }

    ~FakeLink() override
    {
        net_.close(box_);
    }

    std::string host() const override
    {
        return box_->host;
    }

    bool lost() const override
    {
        return box_->lost.load();
    }

    bool ready() const override
    {
        return std::chrono::steady_clock::now() >= box_->publishedAt;
    }

    void send(const std::string& host, const Bytes& datagram) override
    {
        net_.send(*box_, host, datagram);
    }

    std::optional<Bytes> receive(const milliseconds wait) override
    {
        std::unique_lock<std::mutex> lock(box_->mutex);
        if (!box_->arrived.wait_for(lock, wait, [this]() { return !box_->queue.empty(); })) {
            return std::nullopt;
        }
        Bytes got = std::move(box_->queue.front());
        box_->queue.pop_front();
        return got;
    }

private:
    FakeNet& net_;
    std::shared_ptr<FakeNet::Box> box_;
};

struct Person {
    Identity identity = Identity::generate();
    Key sealing = Key::generateSealing();
    Key presence = Key::generateX25519();
    Bytes destKeys = generateI2pMaster().privateKeys;
    std::string dest = i2pRoutingHost(destKeys);

    PresenceAccount account() const
    {
        PresenceAccount account;
        account.fingerprint = identity.fingerprint();
        account.identityPem = identity.privatePem();
        account.sealingPem = sealing.privatePem();
        account.readerKey = presence.rawPrivate();
        account.destKeys = destKeys;
        return account;
    }

    std::string fp() const
    {
        return identity.fingerprint();
    }

    PresenceContact contact() const
    {
        PresenceContact contact;
        contact.fingerprint = identity.fingerprint();
        contact.sealingKeyDer = sealing.publicDer();
        contact.identity = IdentityKeys{identity.classical().publicDer(), identity.pq().publicDer()};
        contact.presenceKeyDer = presence.publicDer();
        contact.presenceDest = dest;
        return contact;
    }
};

class Observer {
public:
    PresenceSink sink()
    {
        return [this](const std::string& peer, const PresenceState& state) {
            std::lock_guard<std::mutex> lock(mutex_);
            states_[peer] = state;
            history_[peer].push_back(state);
        };
    }

    std::vector<PresenceState> history(const std::string& peer)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return history_[peer];
    }

    bool sawSince(const std::string& peer, const std::size_t mark, const PresenceState& state)
    {
        const std::vector<PresenceState> told = history(peer);
        return std::find(told.begin() + static_cast<std::ptrdiff_t>(std::min(mark, told.size())),
                   told.end(), state)
            != told.end();
    }

    PresenceState of(const std::string& peer)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = states_.find(peer);
        return found == states_.end() ? PresenceState{} : found->second;
    }

    bool waitFor(const std::string& peer, const PresenceState& wanted, const milliseconds within = kSettle)
    {
        const auto deadline = std::chrono::steady_clock::now() + within;
        while (std::chrono::steady_clock::now() < deadline) {
            if (of(peer) == wanted) {
                return true;
            }
            std::this_thread::sleep_for(kPoll);
        }
        return of(peer) == wanted;
    }

private:
    std::mutex mutex_;
    std::map<std::string, PresenceState> states_;
    std::map<std::string, std::vector<PresenceState>> history_;
};

bool typeUntilSeen(Presence& typist, const std::string& peer, Observer& watcher,
    const std::string& typistFp)
{
    const auto deadline = std::chrono::steady_clock::now() + kSettle;
    while (std::chrono::steady_clock::now() < deadline) {
        typist.typed(peer);
        if (watcher.of(typistFp) == PresenceState{true, true}) {
            return true;
        }
        std::this_thread::sleep_for(kTypeEvery);
    }
    return false;
}

bool waitUntil(const std::function<bool()>& done)
{
    const auto deadline = std::chrono::steady_clock::now() + kSettle;
    while (!done() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(kPoll);
    }
    return done();
}

PresenceNet netFor(FakeNet& net)
{
    return [&net](const PresenceLinkConfig& config) -> std::unique_ptr<PresenceLink> {
        return std::make_unique<FakeLink>(net, net.open(config));
    };
}

constexpr PresenceState kOffline{false, false};
constexpr PresenceState kOnline{true, false};
constexpr PresenceState kTyping{true, true};

}  // namespace

int main()
{
    FakeNet net;
    const Person alice;
    const Person bob;
    const Person carol;
    const Person dave;
    const Person erin;
    const Person frank;
    const Person gwen;
    const Person hal;
    for (const Person* person : {&alice, &bob, &carol, &dave, &erin, &frank, &gwen, &hal}) {
        net.knowReader(person->presence);
    }

    Observer bobSees;
    Presence bob1(bob.account(), netFor(net), bobSees.sink(), fastTimings());
    bob1.setContacts({alice.contact()});

    Observer aliceSees;
    Presence alice1(alice.account(), netFor(net), aliceSees.sink(), fastTimings());
    alice1.setContacts({bob.contact()});
    Presence alice2(alice.account(), netFor(net), aliceSees.sink(), fastTimings());
    alice2.setContacts({bob.contact()});

    bob1.setFocused(true);
    bob1.watch({alice.fp()});
    std::this_thread::sleep_for(kUnanswered);
    CHECK(bobSees.of(alice.fp()) == kOffline);

    alice1.setFocused(true);
    CHECK(bobSees.waitFor(alice.fp(), kOnline));
    CHECK(net.holdersOf(alice.dest) == 1);

    const std::uint64_t beforeLoss = net.newestGeneration(alice.dest);
    const std::size_t lossMark = bobSees.history(alice.fp()).size();
    net.lose(alice.dest);
    CHECK(waitUntil([&]() { return net.newestGeneration(alice.dest) > beforeLoss; }));
    alice1.watch({bob.fp()});
    CHECK(typeUntilSeen(alice1, bob.fp(), bobSees, alice.fp()));
    CHECK(!bobSees.sawSince(alice.fp(), lossMark, kOffline));
    CHECK(net.holdersOf(alice.dest) == 1);
    CHECK(bobSees.waitFor(alice.fp(), kOnline));
    CHECK(aliceSees.waitFor(bob.fp(), kOnline));

    alice2.setFocused(true);
    CHECK(waitUntil([&]() { return net.holdersOf(alice.dest) == 2; }));
    const std::size_t secondMark = bobSees.history(alice.fp()).size();
    for (int round = 0; round < kTypingRounds; ++round) {
        alice2.typed(bob.fp());
        std::this_thread::sleep_for(kTypeEvery);
    }
    CHECK(!bobSees.sawSince(alice.fp(), secondMark, kTyping));

    const std::size_t moveMark = bobSees.history(alice.fp()).size();
    alice1.setFocused(false);
    CHECK(waitUntil([&]() { return net.holdersOf(alice.dest) == 1; }));
    CHECK(typeUntilSeen(alice2, bob.fp(), bobSees, alice.fp()));
    CHECK(!bobSees.sawSince(alice.fp(), moveMark, kOffline));

    alice2.setFocused(false);
    CHECK(bobSees.waitFor(alice.fp(), kOffline));
    CHECK(waitUntil([&]() { return net.holdersOf(alice.dest) == 0; }));

    {
        Observer carolSees;
        Presence carol1(carol.account(), netFor(net), carolSees.sink(), fastTimings());
        carol1.setContacts({alice.contact()});
        carol1.setFocused(true);
        carol1.watch({alice.fp()});
        alice1.setFocused(true);
        CHECK(bobSees.waitFor(alice.fp(), kOnline));
        std::this_thread::sleep_for(kKnockWait);
        CHECK(carolSees.of(alice.fp()) == kOffline);
        alice1.setFocused(false);
        CHECK(bobSees.waitFor(alice.fp(), kOffline));
    }

    alice1.setFocused(true);
    CHECK(aliceSees.waitFor(bob.fp(), kOnline));
    alice1.setShown(false);
    CHECK(aliceSees.waitFor(bob.fp(), kOffline));
    CHECK(bobSees.waitFor(alice.fp(), kOffline));
    CHECK(waitUntil([&]() { return net.holdersOf(alice.dest) == 0; }));
    const std::size_t watchersHidden = net.watchersOf(alice.presence);
    std::this_thread::sleep_for(kKnockWait);
    CHECK(net.watchersOf(alice.presence) == watchersHidden);
    CHECK(aliceSees.of(bob.fp()) == kOffline);
    CHECK(bobSees.of(alice.fp()) == kOffline);
    alice1.setFocused(false);
    alice1.setShown(true);

    alice1.setFocused(true);
    alice2.setFocused(true);
    CHECK(bobSees.waitFor(alice.fp(), kOnline));
    CHECK(waitUntil([&]() { return net.holdersOf(alice.dest) == 2; }));
    alice1.setFocused(false);
    alice2.setFocused(false);
    CHECK(bobSees.waitFor(alice.fp(), kOffline));

    {
        PresenceTimings slow = fastTimings();
        slow.watchRetry = kSlowRetry;
        slow.subscriptionLife = kLongSilence;
        Observer erinSees;
        Presence erin1(erin.account(), netFor(net), erinSees.sink(), slow);
        erin1.setContacts({frank.contact()});
        erin1.setFocused(true);
        erin1.watch({frank.fp()});
        std::this_thread::sleep_for(kUnanswered);
        Observer frankSees;
        Presence frank1(frank.account(), netFor(net), frankSees.sink(), slow);
        frank1.setContacts({erin.contact()});
        frank1.setFocused(true);
        frank1.watch({erin.fp()});
        CHECK(frankSees.waitFor(erin.fp(), kOnline, kWakeWithin));
        CHECK(erinSees.waitFor(frank.fp(), kOnline, kWakeWithin));
    }

    {
        PresenceTimings stale = fastTimings();
        stale.watchRetry = kStaleRetry;
        stale.subscriptionLife = kLongSilence;
        stale.onlineTail = kShortTail;
        Observer erinSees;
        Presence erin2(erin.account(), netFor(net), erinSees.sink(), stale);
        erin2.setContacts({frank.contact()});
        erin2.setFocused(true);
        erin2.watch({frank.fp()});
        Observer frankSees;
        Presence frank2(frank.account(), netFor(net), frankSees.sink(), stale);
        frank2.setContacts({erin.contact()});
        frank2.setFocused(true);
        frank2.watch({erin.fp()});
        CHECK(erinSees.waitFor(frank.fp(), kOnline));
        CHECK(frankSees.waitFor(erin.fp(), kOnline));
        frank2.setFocused(false);
        CHECK(waitUntil([&]() { return net.holdersOf(frank.dest) == 0; }));
        std::this_thread::sleep_for(kAwayBeforeReturn);
        frank2.setFocused(true);
        CHECK(typeUntilSeen(frank2, erin.fp(), erinSees, frank.fp()));
    }

    {
        alice1.setContacts({bob.contact(), dave.contact()});
        bob1.setContacts({alice.contact(), dave.contact()});
        Observer daveSees;
        Presence dave1(dave.account(), netFor(net), daveSees.sink(), fastTimings());
        dave1.setContacts({alice.contact(), bob.contact()});
        dave1.setFocused(true);
        alice1.setFocused(true);
        dave1.watch({alice.fp(), bob.fp()});
        CHECK(daveSees.waitFor(alice.fp(), kOnline));
        CHECK(daveSees.waitFor(bob.fp(), kOnline));
        {
            PresenceLinkConfig door;
            door.readerKey = dave.presence.rawPrivate();
            FakeLink inbox(net, net.open(door));
            const Key aliceSealing = Key::fromPublicDer(alice.sealing.publicDer());
            const auto knock = [&](const Key& signer) {
                PresenceWatch watch;
                watch.id = randomBytes(kPresenceSubscriptionIdBytes);
                watch.key = randomBytes(kAeadKeyBytes);
                watch.from = dave.fp();
                watch.reply = inbox.host();
                watch.sentAt = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                inbox.send(alice.dest, presenceWatchFrame(watch, signer, aliceSealing));
                return inbox.receive(kKnockWait).has_value();
            };
            CHECK(knock(dave.identity.classical()));
            CHECK(!knock(bob.identity.classical()));
        }
        const std::uint64_t beforeReorder = net.newestGeneration(alice.dest);
        alice1.setContacts({dave.contact(), bob.contact()});
        std::this_thread::sleep_for(kKnockWait);
        CHECK(net.newestGeneration(alice.dest) == beforeReorder);
        dave1.watch({bob.fp()});
        CHECK(daveSees.waitFor(alice.fp(), kOffline));
        std::this_thread::sleep_for(kKnockWait);
        CHECK(daveSees.of(bob.fp()) == kOnline);
        bob1.setContacts({alice.contact()});
    }

    CHECK(bobSees.waitFor(alice.fp(), kOnline));
    alice1.setContacts({});
    CHECK(waitUntil([&]() { return net.holdersOf(alice.dest) == 0; }));
    CHECK(bobSees.waitFor(alice.fp(), kOffline));
    alice1.setFocused(false);

    std::vector<PresenceContact> crowd;
    for (std::size_t index = 0; index < kMaxPresenceReaders + kCrowdBeyondCap; ++index) {
        PresenceContact contact = bob.contact();
        contact.fingerprint = "crowd" + std::to_string(index);
        contact.presenceKeyDer = Key::generateX25519().publicDer();
        crowd.push_back(std::move(contact));
    }
    alice1.setContacts(crowd);
    alice1.setFocused(true);
    CHECK(waitUntil([&]() { return net.readersOf(alice.dest) == i2p::kMaxLeaseSetReaders; }));
    alice1.setFocused(false);

    {
        Observer halSees;
        Presence hal1(hal.account(), netFor(net), halSees.sink(), fastTimings());
        hal1.setContacts({gwen.contact()});
        hal1.setFocused(true);
        hal1.watch({gwen.fp()});
        std::this_thread::sleep_for(kQuietWatch);
        CHECK(halSees.of(gwen.fp()) == kOffline);
        CHECK(net.watchersOf(hal.presence) == 1);
    }

    std::fprintf(stderr, "TestPresence passed\n");
    return 0;
}
