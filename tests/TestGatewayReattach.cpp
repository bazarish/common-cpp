// Bazarish project (c) 2026
#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/I2p.hpp"
#include "bazarish/TrafficShape.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <chrono>
#include <cstdio>
#include <memory>
#include <thread>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kReadyWithin{10};
// Ten ticks of the cover loop, each of which used to try the orphans again.
constexpr std::chrono::seconds kWatchFor{2};
// A decoy burst would close and reopen the control socket inside the watch.
constexpr double kNoBurstSeconds = 3600;
constexpr double kNoBurstCeiling = 2 * kNoBurstSeconds;
constexpr double kPauseAlpha = 1;

i2p::RouterConfig gatewayAt(const int port, const test::FakeGateway& fake)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = test::kFakeGatewayPath;
    config.gatewayFingerprint = fake.fingerprint();
    config.gatewayTls = false;
    config.gatewayReadPause = shape::Pareto{kPauseAlpha, kNoBurstSeconds, kNoBurstCeiling};
    return config;
}

i2p::EndpointConfig bulk()
{
    i2p::EndpointConfig wanted;
    wanted.published = false;
    wanted.bulk = true;
    return wanted;
}

}  // namespace

int main()
try {
    {
        http::Server server(http::Server::Options{});
        test::FakeGateway fake;
        fake.issueTickets();
        fake.refuseJoins();
        const int port = fake.start(server);
        CHECK(port > 0);
        i2p::Router router(gatewayAt(port, fake));
        router.start();
        CHECK(router.waitReady(kReadyWithin));
        const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(bulk());
        const std::size_t afterCreate = fake.socketsOpened();
        std::this_thread::sleep_for(kWatchFor);
        const std::size_t afterWatch = fake.socketsOpened();
        std::printf("refused join: %zu socket(s) after the create, %zu after %lld s; endpoint %s\n",
            afterCreate, afterWatch, static_cast<long long>(kWatchFor.count()),
            endpoint->lost() ? "lost" : "standing");
        CHECK(afterWatch == afterCreate);
        CHECK(endpoint->lost());
        router.stop();
        server.stop();
    }

    {
        http::Server server(http::Server::Options{});
        test::FakeGateway fake;
        const int port = fake.start(server);
        CHECK(port > 0);
        i2p::Router router(gatewayAt(port, fake));
        router.start();
        CHECK(router.waitReady(kReadyWithin));
        const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(bulk());
        const std::size_t afterCreate = fake.socketsOpened();
        std::this_thread::sleep_for(kWatchFor);
        const std::size_t withoutTickets = fake.socketsOpened();
        fake.sendTickets();
        CHECK(testutil::waitFor([&fake]() { return fake.joins() == 1; }));
        std::this_thread::sleep_for(kWatchFor);
        std::printf("no ticket: %zu socket(s) after the create, %zu while it waited, %zu after the "
                    "tickets came; %zu join(s), %zu attach(es)\n",
            afterCreate, withoutTickets, fake.socketsOpened(), fake.joins(),
            fake.framesOf(gateway::FrameType::eAttach));
        CHECK(withoutTickets == afterCreate);
        CHECK(fake.socketsOpened() == afterCreate + 1);
        CHECK(fake.joins() == 1);
        CHECK(fake.framesOf(gateway::FrameType::eAttach) == 1);
        CHECK(!endpoint->lost());
        router.stop();
        server.stop();
    }
    std::fprintf(stderr, "TestGatewayReattach passed\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
