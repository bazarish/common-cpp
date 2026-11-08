// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kQuiet{600};
constexpr std::chrono::seconds kReadyWithin{10};
constexpr std::chrono::seconds kDialFor{60};
constexpr std::chrono::seconds kEndsWithin{5};
constexpr std::chrono::milliseconds kDialUnderWay{300};
const std::string kNobody = std::string(52, 'n') + ".b32.i2p";

}  // namespace

int main()
{
    http::Server server(http::Server::Options{});
    test::FakeGateway fake;
    const int port = fake.start(server);
    CHECK(port > 0);

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

    i2p::EndpointConfig dialling;
    dialling.published = false;
    const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(dialling);
    CHECK(endpoint->waitReady(kReadyWithin));

    std::unique_ptr<i2p::Stream> reached;
    const auto started = std::chrono::steady_clock::now();
    std::thread dial([&]() { reached = endpoint->connect(kNobody, kDialFor); });
    std::this_thread::sleep_for(kDialUnderWay);
    endpoint->stop();
    dial.join();
    CHECK(reached == nullptr);
    CHECK(std::chrono::steady_clock::now() - started < kEndsWithin);
    CHECK(endpoint->connect(kNobody, kDialFor) == nullptr);
    CHECK(std::chrono::steady_clock::now() - started < kEndsWithin);

    router.stop();
    server.stop();
    std::printf("TestGatewayDialStop ok\n");
    return 0;
}
