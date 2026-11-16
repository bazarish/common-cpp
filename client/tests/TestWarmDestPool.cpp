// Bazarish project (c) 2026
#include "WarmDestPool.hpp"

#include "FakeGateway.hpp"

#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kReadyWithin{10};
constexpr std::chrono::milliseconds kPoll{50};
// Longer than two refill rounds of a pool that retried on a one-second tick.
constexpr std::chrono::milliseconds kQuietSpan{2500};
constexpr std::size_t kPoolSize = 2;
constexpr char kShapeRefusal[] = "no shape for this test";

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

    {
        std::mutex mutex;
        std::condition_variable asked;
        int shapes = 0;
        client::WarmDestPool failing(router, kPoolSize, [&]() -> i2p::EndpointConfig {
            {
                const std::lock_guard<std::mutex> lock(mutex);
                ++shapes;
            }
            asked.notify_all();
            throw std::runtime_error(kShapeRefusal);
        });
        failing.start();
        std::this_thread::sleep_for(kQuietSpan);
        {
            const std::lock_guard<std::mutex> lock(mutex);
            CHECK(shapes == 1);
        }
        CHECK(failing.failure() == std::string(kShapeRefusal));
        CHECK(failing.acquire(i2p::Privacy::eMax) == nullptr);
        {
            std::unique_lock<std::mutex> lock(mutex);
            CHECK(asked.wait_for(lock, kReadyWithin, [&shapes]() { return shapes == 2; }));
        }
        failing.stop();
    }

    router.stop();
    server.stop();
    return 0;
} catch (...) {
    return testutil::failed();
}
