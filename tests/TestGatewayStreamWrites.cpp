// Bazarish project (c) 2026
#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/I2p.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <chrono>
#include <cstdio>
#include <exception>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kReadyWithin{10};
constexpr std::chrono::seconds kDialWithin{10};
constexpr const char* kPeer = test::kFakeGatewayHost;
// Each stream fills its window at once: together they outgrow what the sockets buffer.
constexpr std::size_t kFillingStreams = 40;
// Far past the farewell's bound: a stop that waits for the gateway shows.
constexpr std::chrono::seconds kGatewayStalls{3};
// The farewell's 200 ms, a cover tick the router's thread may be in, and the joins.
constexpr std::chrono::milliseconds kStopWithin{1000};

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

i2p::EndpointConfig unpublished()
{
    i2p::EndpointConfig wanted;
    wanted.published = false;
    return wanted;
}

}  // namespace

int main()
{
    {
        http::Server server(http::Server::Options{});
        test::FakeGateway fake;
        const int port = fake.start(server);
        CHECK(port > 0);
        fake.answerStreams();
        i2p::Router router(gatewayAt(port, fake));
        router.start();
        CHECK(router.waitReady(kReadyWithin));
        const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(unpublished());
        const std::unique_ptr<i2p::Stream> stream = endpoint->connect(kPeer, kDialWithin);
        CHECK(stream != nullptr);

        const Bytes twoWindows(2 * gateway::kStreamWindowBytes, 'w');
        bool refused = false;
        std::thread writing([&]() {
            try {
                stream->writeAll(twoWindows);
            } catch (const std::exception&) {
                refused = true;
            }
        });
        CHECK(testutil::waitFor(
            [&fake]() { return fake.streamBytes() >= gateway::kStreamWindowBytes; }));
        fake.resetStreams();
        writing.join();
        CHECK(refused);
        CHECK_THROWS(stream->writeAll(twoWindows));

        router.stop();
        server.stop();
    }

    {
        http::Server server(http::Server::Options{});
        test::FakeGateway fake;
        const int port = fake.start(server);
        CHECK(port > 0);
        fake.answerStreams();
        i2p::Router router(gatewayAt(port, fake));
        router.start();
        CHECK(router.waitReady(kReadyWithin));
        const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(unpublished());
        std::vector<std::unique_ptr<i2p::Stream>> streams;
        for (std::size_t i = 0; i < kFillingStreams; ++i) {
            streams.push_back(endpoint->connect(kPeer, kDialWithin));
            CHECK(streams.back() != nullptr);
        }

        fake.holdReading(true);
        const Bytes window(gateway::kStreamWindowBytes, 'f');
        for (const std::unique_ptr<i2p::Stream>& stream : streams) {
            stream->writeAll(window);
        }
        std::thread release([&fake]() {
            std::this_thread::sleep_for(kGatewayStalls);
            fake.holdReading(false);
        });
        const auto stopping = std::chrono::steady_clock::now();
        router.stop();
        const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - stopping);
        std::printf("a stop with the gateway not reading took %lld ms\n",
            static_cast<long long>(took.count()));
        CHECK(took < kStopWithin);
        release.join();
        server.stop();
    }

    {
        http::Server server(http::Server::Options{});
        test::FakeGateway fake;
        const int port = fake.start(server);
        CHECK(port > 0);
        fake.answerStreams();
        i2p::Router router(gatewayAt(port, fake));
        router.start();
        CHECK(router.waitReady(kReadyWithin));
        const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(unpublished());
        const std::unique_ptr<i2p::Stream> stream = endpoint->connect(kPeer, kDialWithin);
        CHECK(stream != nullptr);
        stream->writeAll(Bytes(gateway::kStreamWindowBytes, 'r'));
        router.stop();
        CHECK(testutil::waitFor([&fake]() {
            return fake.framesOf(gateway::FrameType::eEndpointStop) == 1;
        }));
        CHECK(fake.streamBytes() == gateway::kStreamWindowBytes);
        server.stop();
    }
    return 0;
}
