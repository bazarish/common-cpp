// Bazarish project (c) 2026
#include "bazarish/HostCache.hpp"
#include "bazarish/I2p.hpp"

#include "TestUtil.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::dns;
namespace ip = boost::asio::ip;

namespace {

constexpr int kPort = 443;
constexpr int kOtherPort = 8443;
constexpr std::chrono::seconds kTtl{30};
constexpr std::chrono::seconds kStep{1};
constexpr int kCallers = 8;
constexpr std::chrono::milliseconds kCallersSettle{200};
const char* const kHost = "gw.example";
const char* const kOtherHost = "decoy.example";
const char* const kLoopbackName = "localhost";

const ip::address kAddress = ip::make_address("192.0.2.7");

class Clock {
public:
    std::chrono::steady_clock::time_point now() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return now_;
    }
    void advance(const std::chrono::seconds by)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        now_ += by;
    }

private:
    mutable std::mutex mutex_;
    std::chrono::steady_clock::time_point now_ = std::chrono::steady_clock::now();
};

// Counts its lookups; while held, each waits until let go.
class FakeLookup {
public:
    Resolved operator()(const std::string&, int)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        ++calls_;
        changed_.notify_all();
        changed_.wait(lock, [this]() { return !held_; });
        Resolved resolved;
        if (failing_) {
            resolved.error = "no such name";
            return resolved;
        }
        resolved.addresses = {kAddress};
        resolved.ttl = kTtl;
        return resolved;
    }

    int calls() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return calls_;
    }
    void hold(const bool held)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            held_ = held;
        }
        changed_.notify_all();
    }
    void fail(const bool failing)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        failing_ = failing;
    }
    void waitCalls(const int count)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        changed_.wait(lock, [this, count]() { return calls_ >= count; });
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    int calls_ = 0;
    bool held_ = false;
    bool failing_ = false;
};

struct Rig {
    Clock clock;
    FakeLookup lookup;
    HostCache cache{[this](const std::string& host, const int port) { return lookup(host, port); },
        [this]() { return clock.now(); }};
};

void checkTtl()
{
    Rig rig;
    CHECK(rig.cache.resolve(kHost, kPort).addresses == std::vector<ip::address>{kAddress});
    CHECK(rig.cache.resolve(kHost, kPort).error.empty());
    CHECK(rig.lookup.calls() == 1);
    rig.clock.advance(kTtl - kStep);
    CHECK(rig.cache.resolve(kHost, kPort).error.empty());
    CHECK(rig.lookup.calls() == 1);
    rig.clock.advance(kStep);
    CHECK(rig.cache.resolve(kHost, kPort).error.empty());
    CHECK(rig.lookup.calls() == 2);

    CHECK(rig.cache.resolve(kHost, kOtherPort).error.empty());
    CHECK(rig.cache.resolve(kOtherHost, kPort).error.empty());
    CHECK(rig.lookup.calls() == 4);
    CHECK(rig.cache.size() == 3);
}

void checkFailureNotKept()
{
    Rig rig;
    rig.lookup.fail(true);
    CHECK(!rig.cache.resolve(kHost, kPort).error.empty());
    CHECK(!rig.cache.resolve(kHost, kPort).error.empty());
    CHECK(rig.lookup.calls() == 2);
    CHECK(rig.cache.size() == 0);
}

void checkSharedInFlight()
{
    Rig rig;
    rig.lookup.hold(true);
    std::atomic<int> answered{0};
    std::vector<std::thread> callers;
    for (int caller = 0; caller < kCallers; ++caller) {
        callers.emplace_back([&rig, &answered]() {
            if (rig.cache.resolve(kHost, kPort).addresses == std::vector<ip::address>{kAddress}) {
                ++answered;
            }
        });
    }
    rig.lookup.waitCalls(1);
    std::this_thread::sleep_for(kCallersSettle);
    CHECK(answered.load() == 0);
    rig.lookup.hold(false);
    for (std::thread& caller : callers) {
        caller.join();
    }
    CHECK(answered.load() == kCallers);
    CHECK(rig.lookup.calls() == 1);
}

void checkInvalidation()
{
    Rig rig;
    CHECK(rig.cache.resolve(kHost, kPort).error.empty());
    rig.cache.invalidate();
    CHECK(rig.cache.size() == 0);
    CHECK(rig.cache.resolve(kHost, kPort).error.empty());
    CHECK(rig.lookup.calls() == 2);

    rig.lookup.hold(true);
    rig.clock.advance(kTtl);
    std::thread before([&rig]() { CHECK(rig.cache.resolve(kHost, kPort).error.empty()); });
    rig.lookup.waitCalls(3);
    rig.cache.invalidate();
    std::thread after([&rig]() { CHECK(rig.cache.resolve(kHost, kPort).error.empty()); });
    rig.lookup.waitCalls(4);
    rig.lookup.hold(false);
    before.join();
    after.join();
    CHECK(rig.lookup.calls() == 4);
    CHECK(rig.cache.size() == 1);
}

void checkNetworkChangeEmptiesTheProcessCache()
{
    CHECK(hostCache().resolve(kLoopbackName, kPort).error.empty());
    CHECK(hostCache().size() == 1);
    i2p::networkChanged();
    CHECK(hostCache().size() == 0);
    CHECK(hostCache().resolve(kLoopbackName, kPort).error.empty());
    CHECK(hostCache().size() == 1);
    i2p::networkLost();
    CHECK(hostCache().size() == 0);
    i2p::networkChanged();
}

}  // namespace

int main()
{
    checkTtl();
    checkFailureNotKept();
    checkSharedInFlight();
    checkInvalidation();
    checkNetworkChangeEmptiesTheProcessCache();
    std::puts("TestHostCache ok");
    return 0;
}
