// Bazarish project (c) 2026
#include "WarmDestPool.hpp"

#include "FakeGateway.hpp"

#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kQuiet{600};
constexpr std::chrono::seconds kReadyWithin{10};
constexpr std::chrono::milliseconds kPoll{50};
constexpr std::size_t kPoolSize = 2;

std::shared_ptr<i2p::Endpoint> warmWithin(client::WarmDestPool& pool, const i2p::Privacy privacy)
{
    const auto deadline = std::chrono::steady_clock::now() + kReadyWithin;
    while (std::chrono::steady_clock::now() < deadline) {
        if (std::shared_ptr<i2p::Endpoint> warm = pool.acquire(privacy)) {
            return warm;
        }
        std::this_thread::sleep_for(kPoll);
    }
    return nullptr;
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
    config.gatewayControlMinLife = kQuiet;
    config.gatewayControlMaxLife = kQuiet;
    config.gatewayDecoyMin = kQuiet;
    config.gatewayDecoyMax = kQuiet;
    i2p::Router router(config);
    router.start();
    CHECK(router.waitReady(kReadyWithin));

    std::atomic<i2p::Privacy> chosen{i2p::Privacy::eMinimal};
    {
        client::WarmDestPool pool(router, kPoolSize, [&chosen]() {
            i2p::EndpointConfig shape;
            shape.privacy = chosen.load();
            shape.published = false;
            return shape;
        });
        pool.start();
        CHECK(warmWithin(pool, i2p::Privacy::eMinimal) != nullptr);
        CHECK(pool.acquire(i2p::Privacy::eMax) == nullptr);

        chosen.store(i2p::Privacy::eMax);
        pool.flush();
        CHECK(warmWithin(pool, i2p::Privacy::eMax) != nullptr);
        pool.stop();
    }

    router.stop();
    server.stop();
    return 0;
}
