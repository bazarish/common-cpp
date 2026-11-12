// Bazarish project (c) 2026
#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/I2p.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kQuiet{600};
constexpr std::chrono::seconds kReadyWithin{10};
constexpr std::int64_t kOldPublished = 1'800'000'000;
constexpr std::int64_t kNewPublished = kOldPublished + 30;
constexpr std::int64_t kLeaseSeconds = 600;
const std::string kRecipient = "recipient.b32.i2p";

}  // namespace

int main()
{
    {
        i2p::LeaseSetRefresh refresh;
        refresh.before = i2p::LeaseSetSeen{kOldPublished, kOldPublished + kLeaseSeconds};
        const i2p::LeaseSetRefresh back
            = gateway::leaseSetRefreshFromJson(gateway::leaseSetRefreshJson(refresh));
        CHECK(back.before.has_value() && back.before->publishedAt == kOldPublished
            && back.before->expiresAt == kOldPublished + kLeaseSeconds);
        CHECK(!back.after.has_value());
        CHECK(i2p::publishedLater(*refresh.before, std::nullopt));
        const i2p::LeaseSetSeen newer{kNewPublished, kNewPublished + kLeaseSeconds};
        CHECK(i2p::publishedLater(newer, refresh.before));
        CHECK(!i2p::publishedLater(*refresh.before, refresh.before));
    }

    http::Server server(http::Server::Options{});
    test::FakeGateway fake;
    const int port = fake.start(server);
    CHECK(port > 0);
    i2p::LeaseSetRefresh scripted;
    scripted.before = i2p::LeaseSetSeen{kOldPublished, kOldPublished + kLeaseSeconds};
    scripted.after = i2p::LeaseSetSeen{kNewPublished, kNewPublished + kLeaseSeconds};
    fake.answerLookups(scripted);

    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = test::kFakeGatewayPath;
    config.gatewayFingerprint = fake.fingerprint();
    config.gatewayTls = false;
    config.gatewayControlMinLife = kQuiet;
    config.gatewayControlMaxLife = kQuiet;
    config.gatewayDecoyMin = kQuiet;
    config.gatewayDecoyMax = kQuiet;
    i2p::Router router(config);
    router.start();
    CHECK(router.waitReady(kReadyWithin));
    CHECK(router.capabilities().leaseSetRefresh);

    i2p::EndpointConfig wanted;
    wanted.published = false;
    const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(wanted);
    const i2p::LeaseSetRefresh told = router.refreshLeaseSet(endpoint->routingHost(), kRecipient);
    CHECK(told.before.has_value() && told.before->publishedAt == kOldPublished);
    CHECK(told.after.has_value() && told.after->publishedAt == kNewPublished);
    const std::vector<nlohmann::json> asked = fake.lookups();
    CHECK(asked.size() == 1);
    CHECK(asked.front().value("host", std::string()) == kRecipient);
    CHECK_THROWS(router.refreshLeaseSet("stranger.b32.i2p", kRecipient));

    router.stop();
    server.stop();
    return 0;
}
