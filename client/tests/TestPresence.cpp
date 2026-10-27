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

PresenceTimings fastTimings()
{
    PresenceTimings timings;
    timings.watchRetry = milliseconds(100);
    timings.renewEvery = milliseconds(300);
    timings.subscriptionLife = milliseconds(900);
    timings.siblingKeepalive = milliseconds(150);
    timings.holderSilence = milliseconds(900);
    timings.probeDeadline = milliseconds(600);
    timings.onlineTail = milliseconds(800);
    timings.typingPulse = milliseconds(500);
    timings.typingResend = milliseconds(100);
    timings.readersSettle = milliseconds(200);
    timings.selfCheckEvery = milliseconds(400);
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
        live_.push_back(box);
        return box;
    }

    void close(const std::shared_ptr<Box>& box)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::erase(live_, box);
    }

    void send(const Box& from, const std::string& host, const Bytes& datagram)
    {
        std::shared_ptr<Box> target;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const std::shared_ptr<Box>& box : live_) {
                if (box->host == host && (!target || box->generation > target->generation)) {
                    target = box;
                }
            }
        }
        if (!target) {
            return;
        }
        if (!target->readers.empty()
            && std::find(target->readers.begin(), target->readers.end(), from.readerPublic)
                == target->readers.end()) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(target->mutex);
            target->queue.push_back(datagram);
        }
        target->arrived.notify_all();
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

    PresenceAccount account(const std::string& device) const
    {
        PresenceAccount account;
        account.fingerprint = identity.fingerprint();
        account.device = device;
        account.identityPem = identity.privatePem();
        account.sealingPem = sealing.privatePem();
        account.identity = IdentityKeys{identity.classical().publicDer(), identity.pq().publicDer()};
        account.presenceKeyDer = presence.publicDer();
        account.readerKey = presence.rawPrivate();
        account.destKeys = destKeys;
        account.dest = dest;
        return account;
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
        };
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
};

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
    for (const Person* person : {&alice, &bob, &carol, &dave}) {
        net.knowReader(person->presence);
    }

    Observer bobSees;
    Presence bob1(bob.account("b1"), netFor(net), bobSees.sink(), fastTimings());
    bob1.setContacts({alice.contact()});

    Observer aliceSees;
    Presence alice1(alice.account("a1"), netFor(net), aliceSees.sink(), fastTimings());
    alice1.setContacts({bob.contact()});
    Presence alice2(alice.account("a2"), netFor(net), aliceSees.sink(), fastTimings());
    alice2.setContacts({bob.contact()});

    bob1.setFocused(true);
    bob1.watch({alice.identity.fingerprint()});
    std::this_thread::sleep_for(milliseconds(400));
    CHECK(bobSees.of(alice.identity.fingerprint()) == kOffline);

    alice1.setFocused(true);
    CHECK(bobSees.waitFor(alice.identity.fingerprint(), kOnline));
    CHECK(net.holdersOf(alice.dest) == 1);

    alice1.watch({bob.identity.fingerprint()});
    alice1.typed(bob.identity.fingerprint());
    CHECK(bobSees.waitFor(alice.identity.fingerprint(), kTyping));
    CHECK(bobSees.waitFor(alice.identity.fingerprint(), kOnline));
    CHECK(aliceSees.waitFor(bob.identity.fingerprint(), kOnline));

    alice2.setFocused(true);
    std::this_thread::sleep_for(milliseconds(1200));
    CHECK(net.holdersOf(alice.dest) == 1);

    alice1.setFocused(false);
    std::this_thread::sleep_for(milliseconds(1500));
    CHECK(bobSees.of(alice.identity.fingerprint()) == kOnline);
    alice2.typed(bob.identity.fingerprint());
    CHECK(bobSees.waitFor(alice.identity.fingerprint(), kTyping));

    alice2.setFocused(false);
    CHECK(bobSees.waitFor(alice.identity.fingerprint(), kOffline, milliseconds(8000)));

    {
        Observer carolSees;
        Presence carol1(carol.account("c1"), netFor(net), carolSees.sink(), fastTimings());
        carol1.setContacts({alice.contact()});
        carol1.setFocused(true);
        carol1.watch({alice.identity.fingerprint()});
        alice1.setFocused(true);
        CHECK(bobSees.waitFor(alice.identity.fingerprint(), kOnline));
        std::this_thread::sleep_for(milliseconds(1500));
        CHECK(carolSees.of(alice.identity.fingerprint()) == kOffline);
        alice1.setFocused(false);
        CHECK(bobSees.waitFor(alice.identity.fingerprint(), kOffline, milliseconds(8000)));
    }

    alice1.setShown(false);
    alice2.setShown(false);
    alice1.setFocused(true);
    std::this_thread::sleep_for(milliseconds(1500));
    CHECK(bobSees.of(alice.identity.fingerprint()) == kOffline);
    CHECK(net.holdersOf(alice.dest) == 0);
    alice1.setFocused(false);
    alice1.setShown(true);
    alice2.setShown(true);

    alice1.setFocused(true);
    alice2.setFocused(true);
    CHECK(bobSees.waitFor(alice.identity.fingerprint(), kOnline));
    std::this_thread::sleep_for(milliseconds(2500));
    CHECK(net.holdersOf(alice.dest) == 1);
    alice1.typed(bob.identity.fingerprint());
    CHECK(bobSees.waitFor(alice.identity.fingerprint(), kTyping));
    CHECK(bobSees.waitFor(alice.identity.fingerprint(), kOnline));
    alice2.typed(bob.identity.fingerprint());
    CHECK(bobSees.waitFor(alice.identity.fingerprint(), kTyping));
    alice1.setFocused(false);
    alice2.setFocused(false);
    CHECK(bobSees.waitFor(alice.identity.fingerprint(), kOffline, milliseconds(8000)));

    {
        alice1.setContacts({bob.contact(), dave.contact()});
        alice2.setContacts({bob.contact(), dave.contact()});
        bob1.setContacts({alice.contact(), dave.contact()});
        Observer daveSees;
        Presence dave1(dave.account("d1"), netFor(net), daveSees.sink(), fastTimings());
        dave1.setContacts({alice.contact(), bob.contact()});
        dave1.setFocused(true);
        alice1.setFocused(true);
        dave1.watch({alice.identity.fingerprint(), bob.identity.fingerprint()});
        CHECK(daveSees.waitFor(alice.identity.fingerprint(), kOnline));
        CHECK(daveSees.waitFor(bob.identity.fingerprint(), kOnline));
        {
            PresenceLinkConfig door;
            door.readerKey = dave.presence.rawPrivate();
            FakeLink inbox(net, net.open(door));
            const Key aliceSealing = Key::fromPublicDer(alice.sealing.publicDer());
            const auto knock = [&](const Key& signer) {
                PresenceWatch watch;
                watch.id = randomBytes(kPresenceSubscriptionIdBytes);
                watch.key = randomBytes(kAeadKeyBytes);
                watch.from = dave.identity.fingerprint();
                watch.device = "d9";
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
        dave1.watch({bob.identity.fingerprint()});
        CHECK(daveSees.waitFor(alice.identity.fingerprint(), kOffline));
        std::this_thread::sleep_for(milliseconds(1500));
        CHECK(daveSees.of(bob.identity.fingerprint()) == kOnline);
        alice1.setFocused(false);
        CHECK(bobSees.waitFor(alice.identity.fingerprint(), kOffline, milliseconds(8000)));
        bob1.setContacts({alice.contact()});
    }

    alice1.setContacts({});
    alice2.setContacts({});
    alice1.setFocused(true);
    std::this_thread::sleep_for(milliseconds(1500));
    CHECK(net.holdersOf(alice.dest) == 1);
    CHECK(bobSees.of(alice.identity.fingerprint()) == kOffline);
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
    const auto crowdDeadline = std::chrono::steady_clock::now() + kSettle;
    while (net.readersOf(alice.dest) != i2p::kMaxLeaseSetReaders
        && std::chrono::steady_clock::now() < crowdDeadline) {
        std::this_thread::sleep_for(kPoll);
    }
    CHECK(net.readersOf(alice.dest) == i2p::kMaxLeaseSetReaders);
    alice1.setFocused(false);

    std::fprintf(stderr, "TestPresence passed\n");
    return 0;
}
