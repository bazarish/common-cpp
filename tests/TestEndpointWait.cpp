// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <stop_token>
#include <thread>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kReadyWithin{10};
constexpr std::chrono::seconds kLongWait{60};
constexpr std::chrono::seconds kEndsWithin{5};
constexpr std::chrono::milliseconds kWaitUnderWay{200};

std::shared_ptr<i2p::Endpoint> building(i2p::Router& router)
{
    i2p::EndpointConfig shape;
    shape.published = false;
    const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(shape);
    CHECK(!endpoint->ready());
    return endpoint;
}

template <class Act>
std::chrono::steady_clock::duration waitedFor(
    i2p::Endpoint& endpoint, const std::stop_token& stop, bool& ready, Act act)
{
    const auto started = std::chrono::steady_clock::now();
    std::thread actor([&act]() {
        std::this_thread::sleep_for(kWaitUnderWay);
        act();
    });
    ready = endpoint.waitReady(kLongWait, stop);
    actor.join();
    return std::chrono::steady_clock::now() - started;
}

}  // namespace

int main()
try {
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
    i2p::Router router(config);
    router.start();
    CHECK(router.waitReady(kReadyWithin));
    fake.holdReadiness();

    {
        const std::shared_ptr<i2p::Endpoint> endpoint = building(router);
        std::stop_source cancel;
        bool ready = true;
        CHECK(waitedFor(*endpoint, cancel.get_token(), ready, [&cancel]() {
            cancel.request_stop();
        }) < kEndsWithin);
        CHECK(!ready);
    }

    {
        const std::shared_ptr<i2p::Endpoint> endpoint = building(router);
        std::atomic<int> told{0};
        const i2p::EndpointWatch watch(*endpoint, [&told]() { ++told; });
        bool ready = false;
        CHECK(waitedFor(*endpoint, {}, ready, [&fake]() { fake.reportReady(); }) < kEndsWithin);
        CHECK(ready);
        CHECK(testutil::waitFor([&told]() { return told.load() > 0; }));
    }

    {
        const std::shared_ptr<i2p::Endpoint> endpoint = building(router);
        bool ready = true;
        CHECK(waitedFor(*endpoint, {}, ready, [&endpoint]() { endpoint->stop(); }) < kEndsWithin);
        CHECK(!ready);
        CHECK(endpoint->lost());
    }

    router.stop();
    server.stop();
    std::printf("TestEndpointWait ok\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
