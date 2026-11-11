// Bazarish project (c) 2026
#include "I2pKeys.hpp"
#include "I2pRouter.hpp"
#include "Presence.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>

#include "TestUtil.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;
using std::chrono::milliseconds;

namespace {

constexpr char kWarmWatcher[] = "Warm watcher";
constexpr char kWarmReserve[] = "Warm reserve";
constexpr char kPresenceWatcher[] = "Presence watcher";
constexpr char kPresenceAddress[] = "Presence address";
constexpr char kAlice[] = "alice";
constexpr char kBob[] = "bob";
constexpr milliseconds kQuietSpell{2000};
constexpr milliseconds kTick{20};

PresenceTimings testTimings()
{
    PresenceTimings timings;
    timings.tick = kTick;
    return timings;
}

struct Person {
    Identity identity = Identity::generate();
    Key sealing = Key::generateSealing();
    Key presence = Key::generateX25519();
    Bytes destKeys = generateI2pMaster().privateKeys;

    PresenceAccount account(const bool shown) const
    {
        PresenceAccount account;
        account.fingerprint = identity.fingerprint();
        account.identityPem = identity.privatePem();
        account.sealingPem = sealing.privatePem();
        account.readerKey = presence.rawPrivate();
        account.destKeys = destKeys;
        account.shown = shown;
        return account;
    }

    PresenceContact contact() const
    {
        PresenceContact contact;
        contact.fingerprint = identity.fingerprint();
        contact.sealingKeyDer = sealing.publicDer();
        contact.identity = IdentityKeys{identity.classical().publicDer(), identity.pq().publicDer()};
        contact.presenceKeyDer = presence.publicDer();
        contact.presenceDest = i2pRoutingHost(destKeys);
        return contact;
    }
};

bool isPresenceLabel(const std::string& label)
{
    return label == kWarmWatcher || label == kPresenceWatcher || label == kPresenceAddress;
}

std::vector<i2p::LocalDestination> presenceDests(const i2p::Router& router)
{
    std::vector<i2p::LocalDestination> found = router.localDestinations();
    std::erase_if(found, [](const i2p::LocalDestination& dest) {
        return !isPresenceLabel(dest.label);
    });
    return found;
}

std::size_t countOf(const i2p::Router& router, const std::string& label)
{
    const std::vector<i2p::LocalDestination> all = router.localDestinations();
    return static_cast<std::size_t>(std::count_if(all.begin(), all.end(),
        [&label](const i2p::LocalDestination& dest) { return dest.label == label; }));
}

std::set<std::string> hostsOf(const i2p::Router& router, const std::string& owner)
{
    std::set<std::string> hosts;
    for (const i2p::LocalDestination& dest : presenceDests(router)) {
        if (dest.owner == owner) {
            hosts.insert(dest.host);
        }
    }
    return hosts;
}

bool ownsBoth(const i2p::Router& router, const std::string& owner)
{
    bool watcher = false;
    bool address = false;
    for (const i2p::LocalDestination& dest : presenceDests(router)) {
        if (dest.owner != owner) {
            continue;
        }
        watcher = watcher || dest.label == kPresenceWatcher;
        address = address || dest.label == kPresenceAddress;
    }
    return watcher && address;
}

std::unique_ptr<Presence> openPresence(const Person& person, const bool shown,
    const std::filesystem::path& routerDir, const std::string& owner, const Person& contact)
{
    auto presence = std::make_unique<Presence>(person.account(shown),
        i2pPresenceNet(routerDir, owner), [](const std::string&, const PresenceState&) {},
        testTimings());
    presence->setContacts({contact.contact()});
    presence->watch({contact.identity.fingerprint()});
    presence->setFocused(true);
    return presence;
}

}  // namespace

int main()
{
    const std::filesystem::path dataDir = testutil::freshDir("presence-dests");
    setReseedFile(dataDir / "no-reseed.su3");
    i2p::Router& router = sharedI2pRouter(dataDir);
    CHECK(router.capabilities().lateReaderKey);
    CHECK(testutil::waitFor([&router]() { return countOf(router, kWarmReserve) > 0; }));
    CHECK(presenceDests(router).empty());

    const Person alice;
    const Person bob;
    const Person carol;
    std::unique_ptr<Presence> alicePresence = openPresence(alice, false, dataDir, kAlice, carol);
    std::unique_ptr<Presence> bobPresence = openPresence(bob, false, dataDir, kBob, carol);
    std::this_thread::sleep_for(kQuietSpell);
    CHECK(presenceDests(router).empty());

    alicePresence->setShown(true);
    bobPresence->setShown(true);
    CHECK(testutil::waitFor([&router]() {
        return ownsBoth(router, kAlice) && ownsBoth(router, kBob)
            && countOf(router, kWarmWatcher) > 0;
    }));
    const std::set<std::string> aliceHosts = hostsOf(router, kAlice);
    const std::set<std::string> bobHosts = hostsOf(router, kBob);
    CHECK(std::none_of(aliceHosts.begin(), aliceHosts.end(),
        [&bobHosts](const std::string& host) { return bobHosts.contains(host); }));

    alicePresence->setShown(false);
    CHECK(testutil::waitFor([&router]() { return hostsOf(router, kAlice).empty(); }));
    std::this_thread::sleep_for(kQuietSpell);
    CHECK(hostsOf(router, kAlice).empty());
    CHECK(hostsOf(router, kBob) == bobHosts);
    CHECK(countOf(router, kWarmWatcher) > 0);

    alicePresence.reset();
    std::this_thread::sleep_for(kQuietSpell);
    CHECK(hostsOf(router, kBob) == bobHosts);
    CHECK(countOf(router, kWarmWatcher) > 0);

    bobPresence->setShown(false);
    CHECK(testutil::waitFor([&router]() { return presenceDests(router).empty(); }));
    std::this_thread::sleep_for(kQuietSpell);
    CHECK(presenceDests(router).empty());
    CHECK(countOf(router, kWarmReserve) > 0);

    bobPresence->setShown(true);
    CHECK(testutil::waitFor([&router]() {
        return ownsBoth(router, kBob) && countOf(router, kWarmWatcher) > 0;
    }));
    bobPresence.reset();
    CHECK(testutil::waitFor([&router]() { return presenceDests(router).empty(); }));

    const std::string sameName = "Same name";
    const std::string facade = bazarish::i2p::routingHost(
        bazarish::i2p::Keys::generate().publicBase64());
    const std::shared_ptr<bazarish::i2p::Endpoint> first
        = facadeLinkFor(kAlice, sameName, bazarish::i2p::Privacy::eMinimal, facade);
    const std::shared_ptr<bazarish::i2p::Endpoint> second
        = facadeLinkFor(kBob, sameName, bazarish::i2p::Privacy::eMinimal, facade);
    CHECK(first && second && first != second);
    CHECK(first->routingHost() != second->routingHost());
    CHECK(facadeLinkFor(kAlice, sameName, bazarish::i2p::Privacy::eMinimal, facade) == first);
    stopFacadeLinkFor(kAlice);
    CHECK(facadeLinkFor(kBob, sameName, bazarish::i2p::Privacy::eMinimal, facade) == second);

    retireI2pRouter();
    std::filesystem::remove_all(dataDir);
    return 0;
}
