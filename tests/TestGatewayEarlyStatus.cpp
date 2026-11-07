// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kQuiet{600};
constexpr std::chrono::seconds kReadyWithin{10};

}  // namespace

int main()
{
    http::Server server(http::Server::Options{});
    const int port = test::startFakeGateway(server);
    CHECK(port > 0);

    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = test::kFakeGatewayPath;
    config.gatewayToken = "any";
    config.gatewayTls = false;
    config.gatewayControlMinLife = kQuiet;
    config.gatewayControlMaxLife = kQuiet;
    config.gatewayDecoyMin = kQuiet;
    config.gatewayDecoyMax = kQuiet;
    i2p::Router router(config);
    router.start();
    CHECK(router.waitReady(kReadyWithin));

    i2p::EndpointConfig wanted;
    wanted.published = false;
    const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(wanted);
    CHECK(endpoint->routingHost() == test::kFakeGatewayHost);
    CHECK(endpoint->ready());

    router.stop();
    server.stop();
    return 0;
}
