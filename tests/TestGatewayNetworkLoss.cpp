// Bazarish project (c) 2026
#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/I2p.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

using namespace bazarish;

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::chrono::seconds kReadyWithin{10};
constexpr std::chrono::seconds kDialFor{60};
constexpr std::chrono::seconds kEndsWithin{2};
constexpr std::chrono::milliseconds kCallUnderWay{300};
constexpr std::chrono::milliseconds kStatePoll{20};
const std::string kNobody = std::string(52, 'n') + ".b32.i2p";

std::size_t createsHeard(test::FakeGateway& fake)
{
    std::size_t creates = 0;
    for (const Bytes& frame : fake.received()) {
        if (gateway::decode(frame).type == gateway::FrameType::eEndpointCreate) {
            ++creates;
        }
    }
    return creates;
}

bool createFails(i2p::Router& router)
{
    try {
        (void)router.createEndpoint(i2p::EndpointConfig{});
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

bool reachesState(const i2p::TransportState wanted)
{
    const auto until = Clock::now() + kReadyWithin;
    while (Clock::now() < until) {
        if (i2p::transportState() == wanted) {
            return true;
        }
        std::this_thread::sleep_for(kStatePoll);
    }
    return false;
}

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
    std::atomic<int> told{0};
    const i2p::TransportWatch watch([&told]() { ++told; });
    i2p::Router router(config);
    router.start();
    CHECK(router.waitReady(kReadyWithin));

    const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(i2p::EndpointConfig{});
    CHECK(endpoint->waitReady(kReadyWithin));
    CHECK(createsHeard(fake) == 1);

    {
        std::unique_ptr<i2p::Stream> reached;
        const auto started = Clock::now();
        std::thread dial([&]() { reached = endpoint->connect(kNobody, kDialFor); });
        std::this_thread::sleep_for(kCallUnderWay);
        i2p::networkLost();
        dial.join();
        CHECK(reached == nullptr);
        CHECK(Clock::now() - started < kEndsWithin);
        CHECK(i2p::networkDown());
        CHECK(i2p::transportState() == i2p::TransportState::eNoNetwork);
        CHECK(told.load() == 1);
    }

    {
        const auto started = Clock::now();
        CHECK(endpoint->connect(kNobody, kDialFor) == nullptr);
        CHECK(createFails(router));
        CHECK(Clock::now() - started < kEndsWithin);
    }

    i2p::networkChanged();
    CHECK(!i2p::networkDown());
    CHECK(i2p::transportState() == i2p::TransportState::eUp);
    CHECK(told.load() == 2);
    const std::shared_ptr<i2p::Endpoint> after = router.createEndpoint(i2p::EndpointConfig{});
    CHECK(after->waitReady(kReadyWithin));
    CHECK(createsHeard(fake) == 2);

    fake.closeOnHello();
    fake.dropSockets();
    {
        bool failed = false;
        const auto started = Clock::now();
        std::thread create([&]() { failed = createFails(router); });
        std::this_thread::sleep_for(kCallUnderWay);
        i2p::networkLost();
        create.join();
        CHECK(failed);
        CHECK(Clock::now() - started < kEndsWithin);
    }
    fake.acceptHellos();
    i2p::networkChanged();
    const std::shared_ptr<i2p::Endpoint> last = router.createEndpoint(i2p::EndpointConfig{});
    CHECK(last->waitReady(kReadyWithin));
    CHECK(createsHeard(fake) == 3);

    fake.closeOnHello();
    fake.dropSockets();
    CHECK(reachesState(i2p::TransportState::eGatewayUnreachable));
    {
        const auto started = Clock::now();
        CHECK(createFails(router));
        CHECK(last->connect(kNobody, kDialFor) == nullptr);
        CHECK(Clock::now() - started < kEndsWithin);
    }
    fake.acceptHellos();
    CHECK(reachesState(i2p::TransportState::eUp));
    CHECK(router.createEndpoint(i2p::EndpointConfig{})->waitReady(kReadyWithin));
    CHECK(createsHeard(fake) == 4);

    router.stop();
    server.stop();
    std::printf("TestGatewayNetworkLoss ok\n");
    return 0;
}
