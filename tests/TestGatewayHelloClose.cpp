// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"
#include "bazarish/Log.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <chrono>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace bazarish;

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::chrono::seconds kReadyWithin{10};
constexpr std::chrono::milliseconds kFailsWithin{1000};
constexpr std::chrono::seconds kRetriedWithin{5};
constexpr std::size_t kRetriedHellos = 2;
constexpr std::string_view kClosedEarly = "the gateway closed the connection before it was ready";

class Heard {
public:
    void add(const std::string_view message)
    {
        if (message.find(kClosedEarly) == std::string_view::npos) {
            return;
        }
        const std::lock_guard<std::mutex> lock(mutex_);
        at_.push_back(Clock::now());
    }

    std::vector<Clock::time_point> at() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return at_;
    }

private:
    mutable std::mutex mutex_;
    std::vector<Clock::time_point> at_;
};

}  // namespace

int main()
{
    Heard heard;
    log::setTap([&heard](const log::Level level, const std::string_view,
                    const std::string_view message) {
        if (level == log::Level::eWarn) {
            heard.add(message);
        }
    });

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

    fake.closeOnHello();
    {
        i2p::Router refused(config);
        std::string why;
        try {
            refused.start();
        } catch (const std::runtime_error& error) {
            why = error.what();
        }
        CHECK(why.find(kClosedEarly) != std::string::npos);
        const std::vector<Clock::time_point> closed = fake.hellosClosed();
        CHECK(closed.size() == 1);
        CHECK(Clock::now() - closed.front() < kFailsWithin);
    }

    test::FakeGateway welcoming;
    http::Server again(http::Server::Options{});
    config.gatewayPort = welcoming.start(again);
    config.gatewayFingerprint = welcoming.fingerprint();
    CHECK(config.gatewayPort > 0);
    i2p::Router router(config);
    router.start();
    CHECK(router.waitReady(kReadyWithin));

    welcoming.closeOnHello();
    welcoming.dropSockets();
    CHECK(testutil::waitFor(
        [&welcoming]() { return welcoming.hellosClosed().size() >= kRetriedHellos; },
        kRetriedWithin));
    const std::vector<Clock::time_point> closed = welcoming.hellosClosed();
    const std::vector<Clock::time_point> told = heard.at();
    CHECK(!told.empty());
    CHECK(told.front() >= closed.front());
    CHECK(told.front() - closed.front() < kFailsWithin);

    router.stop();
    again.stop();
    server.stop();
    log::setTap({});
    std::printf("TestGatewayHelloClose ok\n");
    return 0;
}
