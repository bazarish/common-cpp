// Bazarish project (c) 2026
#include "GatewayAddress.hpp"
#include "I2pRouter.hpp"
#include "Presence.hpp"
#include "PresenceSeed.hpp"

#include "FakeGateway.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/I2pAddress.hpp>

#include "TestUtil.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace {

// 2026-11-11.
constexpr PresenceDay kDay = 20768;
constexpr std::int64_t kScheduledDays = 2;
constexpr std::int64_t kInOverlap = kPresenceHalfOverlapSeconds - kSecondsPerMinute;
constexpr std::chrono::milliseconds kTick{20};
constexpr std::chrono::milliseconds kWatchRetry{100};
constexpr char kAccountLabel[] = "alice";

std::atomic<std::int64_t> g_utc{presenceDayStart(kDay + 1) - kInOverlap};

struct Seen {
    std::set<std::string> readerKeys;
    std::set<std::string> holderHosts;
    std::set<std::string> delegatedHosts;
    std::set<std::string> leaseSetReaders;
    std::vector<i2p::Keys> keys;
};

std::string i2pBase64Of(const Bytes& raw)
{
    return standardToI2pBase64(toBase64(raw));
}

i2p::Keys keysIn(const nlohmann::json& body)
{
    return i2p::Keys::fromBlob(fromBase64(i2pToStandardBase64(body.at("keys").get<std::string>())));
}

Seen seenIn(const std::vector<Bytes>& frames)
{
    Seen seen;
    for (const Bytes& bytes : frames) {
        const gateway::Frame frame = gateway::decode(ByteView(bytes));
        if (frame.type == gateway::FrameType::eEndpointCreate) {
            const nlohmann::json body = gateway::bodyJson(frame);
            if (body.contains("readerKey")) {
                seen.readerKeys.insert(body.at("readerKey").get<std::string>());
            }
            if (body.contains("keys")) {
                seen.keys.push_back(keysIn(body));
                seen.holderHosts.insert(i2p::routingHost(seen.keys.back().publicBase64()));
                for (const nlohmann::json& reader : body.at("readers")) {
                    seen.leaseSetReaders.insert(reader.get<std::string>());
                }
            }
        }
        if (frame.type == gateway::FrameType::eEndpointDelegate) {
            seen.keys.push_back(keysIn(gateway::bodyJson(frame)));
            seen.delegatedHosts.insert(i2p::routingHost(seen.keys.back().publicBase64()));
        }
    }
    return seen;
}

bool carries(const Bytes& haystack, const Bytes& needle)
{
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end())
        != haystack.end();
}

bool carriesText(const Bytes& haystack, const std::string& needle)
{
    return carries(haystack, Bytes(needle.begin(), needle.end()));
}

}  // namespace

int main()
{
    http::Server server(http::Server::Options{});
    test::FakeGateway gateway;
    const int port = gateway.start(server);
    CHECK(port > 0);
    const std::optional<GatewayAddress> gatewayAt = GatewayAddress::parse("http://127.0.0.1:"
        + std::to_string(port) + test::kFakeGatewayPath + "#" + gateway.fingerprint());
    CHECK(gatewayAt.has_value());
    CHECK(applyI2pTransport([&gatewayAt]() { setGatewayTransport(*gatewayAt); }));
    const std::filesystem::path dataDir = testutil::freshDir("presence-gateway");

    const Identity alice = Identity::generate();
    const Key aliceSealing = Key::generateSealing();
    const PresenceSeed aliceSeed = PresenceSeed::generate();
    const Identity bob = Identity::generate();
    const Key bobSealing = Key::generateSealing();
    const PresenceSeed bobSeed = PresenceSeed::generate();

    PresenceAccount account;
    account.fingerprint = alice.fingerprint();
    account.identityPem = alice.privatePem();
    account.sealingPem = aliceSealing.privatePem();
    account.seed = aliceSeed.bytes();
    PresenceContact contact;
    contact.fingerprint = bob.fingerprint();
    contact.sealingKeyDer = bobSealing.publicDer();
    contact.identity = IdentityKeys{bob.classical().publicDer(), bob.pq().publicDer()};
    contact.schedule = presenceScheduleFrom(bobSeed, kDay, kScheduledDays);
    PresenceTimings timings;
    timings.tick = kTick;
    timings.watchRetry = kWatchRetry;
    timings.utcNow = []() { return g_utc.load(); };

    const std::set<std::string> dayReaderKeys{i2pBase64Of(aliceSeed.readerFor(kDay).rawPrivate()),
        i2pBase64Of(aliceSeed.readerFor(kDay + 1).rawPrivate())};
    const std::set<std::string> dayHosts{aliceSeed.hostFor(kDay), aliceSeed.hostFor(kDay + 1)};
    const std::set<std::string> contactReaders{i2pBase64Of(bobSeed.readerFor(kDay).rawPublic()),
        i2pBase64Of(bobSeed.readerFor(kDay + 1).rawPublic())};
    {
        Presence presence(account, i2pPresenceNet(dataDir, kAccountLabel),
            [](const std::string&, const PresenceState&) {}, timings);
        presence.setContacts({contact});
        presence.watch({bob.fingerprint()});
        presence.setFocused(true);
        CHECK(testutil::waitFor([&]() {
            gateway.askRenewals();
            const Seen seen = seenIn(gateway.received());
            return seen.readerKeys == dayReaderKeys && seen.holderHosts == dayHosts
                && seen.delegatedHosts == dayHosts;
        }));
    }

    const std::vector<Bytes> frames = gateway.received();
    const Seen seen = seenIn(frames);
    CHECK(seen.readerKeys == dayReaderKeys);
    CHECK(seen.holderHosts == dayHosts);
    CHECK(seen.delegatedHosts == dayHosts);
    CHECK(seen.leaseSetReaders == contactReaders);
    for (PresenceDay day = kDay - 1; day <= kDay + kPresenceHorizonDays; ++day) {
        const bool served = day == kDay || day == kDay + 1;
        CHECK(seen.readerKeys.contains(i2pBase64Of(aliceSeed.readerFor(day).rawPrivate())) == served);
    }

    std::vector<Bytes> masterSigningKeys;
    for (const PresenceDay day : {kDay, kDay + 1}) {
        const Bytes master = aliceSeed.destFor(day).blob();
        masterSigningKeys.emplace_back(master.end() - static_cast<std::ptrdiff_t>(kPresenceSeedBytes),
            master.end());
    }
    for (const i2p::Keys& keys : seen.keys) {
        CHECK(keys.isOffline());
        for (const Bytes& signing : masterSigningKeys) {
            CHECK(!carries(keys.blob(), signing));
        }
    }

    const Bytes& seed = aliceSeed.bytes();
    for (const Bytes& frame : frames) {
        CHECK(!carries(frame, seed));
        CHECK(!carriesText(frame, toBase64(seed)));
        CHECK(!carriesText(frame, i2pBase64Of(seed)));
        CHECK(!carriesText(frame, toHex(seed)));
    }

    retireI2pRouter();
    std::filesystem::remove_all(dataDir);
    std::fprintf(stderr, "TestPresenceGateway passed\n");
    return 0;
}
