// Bazarish project (c) 2026
#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/I2p.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <memory>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kReadyWithin{10};
constexpr std::chrono::seconds kDialWithin{10};
constexpr const char* kPeer = test::kFakeGatewayHost;

i2p::RouterConfig gatewayAt(const int port, const test::FakeGateway& fake)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = test::kFakeGatewayPath;
    config.gatewayFingerprint = fake.fingerprint();
    config.gatewayTls = false;
    return config;
}

}  // namespace

int main()
try {
    http::Server server(http::Server::Options{});
    test::FakeGateway fake;
    const int port = fake.start(server);
    CHECK(port > 0);
    fake.answerStreams();
    i2p::Router router(gatewayAt(port, fake));
    router.start();
    CHECK(router.waitReady(kReadyWithin));
    i2p::EndpointConfig wanted;
    wanted.published = false;
    const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(wanted);
    const std::unique_ptr<i2p::Stream> kept = endpoint->connect(kPeer, kDialWithin);
    CHECK(kept != nullptr);

    fake.closeStreams();
    CHECK(testutil::waitFor(
        [&fake]() { return fake.framesOf(gateway::FrameType::eStreamClose) == 1; }));
    std::array<unsigned char, 1> byte{};
    CHECK(kept->readSome(byte) == 0);
    CHECK_THROWS(kept->writeAll(byte));

    router.stop();
    server.stop();
    std::fprintf(stderr, "TestGatewayFarClose passed\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
