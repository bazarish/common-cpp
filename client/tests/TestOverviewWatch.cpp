// Bazarish project (c) 2026
#include "OverviewWatch.hpp"

#include "TestUtil.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish::client;

namespace {

constexpr std::chrono::milliseconds kQuiet{300};

// Answers like the server: a held ask waits for another version or a release.
class FakeServer {
public:
    AccountOverview ask(const std::string& since)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        asked_.push_back(since);
        if (failing_) {
            throw std::runtime_error("no tunnel to the server");
        }
        if (!since.empty()) {
            ++holding_;
            const std::uint64_t releasesBefore = releases_;
            changed_.wait(lock, [&]() {
                return current_.version != since || releases_ != releasesBefore || failing_;
            });
            --holding_;
            if (failing_) {
                throw std::runtime_error("the link broke");
            }
        }
        return current_;
    }

    void release()
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            ++releases_;
        }
        changed_.notify_all();
    }

    void change(const std::string& version, const std::uint64_t usedBytes)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            current_.version = version;
            current_.usage.usedBytes = usedBytes;
        }
        changed_.notify_all();
    }

    void fail(const bool failing)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            failing_ = failing;
        }
        changed_.notify_all();
    }

    std::vector<std::string> asked()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return asked_;
    }

    int holding()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return holding_;
    }

    std::uint64_t releases()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return releases_;
    }

private:
    std::mutex mutex_;
    std::condition_variable changed_;
    AccountOverview current_{"v1", {}, "active", 0, {}, {}};
    std::vector<std::string> asked_;
    int holding_ = 0;
    std::uint64_t releases_ = 0;
    bool failing_ = false;
};

struct Seen {
    std::mutex mutex;
    std::vector<std::string> fresh;
    std::vector<std::string> failures;

    std::size_t freshCount()
    {
        const std::lock_guard<std::mutex> lock(mutex);
        return fresh.size();
    }
    std::size_t failureCount()
    {
        const std::lock_guard<std::mutex> lock(mutex);
        return failures.size();
    }
    std::string lastFresh()
    {
        const std::lock_guard<std::mutex> lock(mutex);
        return fresh.empty() ? std::string() : fresh.back();
    }
};

OverviewWatch::Hooks hooksFor(FakeServer& server, Seen& seen)
{
    return {
        [&server](const std::string& since) { return server.ask(since); },
        [&server]() { server.release(); },
        [&seen](const AccountOverview& overview) {
            const std::lock_guard<std::mutex> lock(seen.mutex);
            seen.fresh.push_back(overview.version);
        },
        [&seen](const std::string& reason) {
            const std::lock_guard<std::mutex> lock(seen.mutex);
            seen.failures.push_back(reason);
        },
    };
}

void testNothingAskedWhileClosed()
{
    FakeServer server;
    Seen seen;
    {
        const OverviewWatch watch(hooksFor(server, seen));
        std::this_thread::sleep_for(kQuiet);
        CHECK(server.asked().empty());
    }
    CHECK(seen.freshCount() == 0);
}

void testOpenDrawsAtOnceThenHolds()
{
    FakeServer server;
    Seen seen;
    OverviewWatch watch(hooksFor(server, seen));
    watch.open();
    CHECK(testutil::waitFor([&]() { return server.holding() == 1; }));
    CHECK(server.asked() == std::vector<std::string>({"", "v1"}));
    CHECK(seen.lastFresh() == "v1");
    std::this_thread::sleep_for(kQuiet);
    CHECK(server.asked().size() == 2);
    CHECK(seen.freshCount() == 1);

    server.change("v2", 1);
    CHECK(testutil::waitFor([&]() { return seen.lastFresh() == "v2"; }));
    CHECK(testutil::waitFor([&]() { return server.holding() == 1; }));
    CHECK(server.asked().back() == "v2");
    CHECK(seen.freshCount() == 2);
}

void testCloseReleasesTheHold()
{
    FakeServer server;
    Seen seen;
    OverviewWatch watch(hooksFor(server, seen));
    watch.open();
    CHECK(testutil::waitFor([&]() { return server.holding() == 1; }));
    watch.close();
    CHECK(server.releases() == 1);
    CHECK(testutil::waitFor([&]() { return server.holding() == 0; }));
    std::this_thread::sleep_for(kQuiet);
    CHECK(server.asked().size() == 2);
    CHECK(seen.freshCount() == 1);

    watch.open();
    CHECK(testutil::waitFor([&]() { return server.holding() == 1; }));
    CHECK(server.asked() == std::vector<std::string>({"", "v1", "", "v1"}));
    CHECK(seen.freshCount() == 2);
}

void testFailureParksUntilTheLinkIsBack()
{
    FakeServer server;
    Seen seen;
    OverviewWatch watch(hooksFor(server, seen));
    watch.open();
    CHECK(testutil::waitFor([&]() { return server.holding() == 1; }));
    server.fail(true);
    CHECK(testutil::waitFor([&]() { return seen.failureCount() == 1; }));
    std::this_thread::sleep_for(kQuiet);
    CHECK(seen.failureCount() == 1);
    CHECK(server.asked().size() == 2);

    server.fail(false);
    watch.linkBack();
    CHECK(testutil::waitFor([&]() { return server.holding() == 1; }));
    CHECK(server.asked().size() == 4);
    CHECK(server.asked().at(2).empty());
    CHECK(seen.freshCount() == 2);
}

void testStopEndsAHeldAsk()
{
    FakeServer server;
    Seen seen;
    {
        OverviewWatch watch(hooksFor(server, seen));
        watch.open();
        CHECK(testutil::waitFor([&]() { return server.holding() == 1; }));
    }
    CHECK(server.holding() == 0);
}

}  // namespace

int main()
try {
    testNothingAskedWhileClosed();
    testOpenDrawsAtOnceThenHolds();
    testCloseReleasesTheHold();
    testFailureParksUntilTheLinkIsBack();
    testStopEndsAHeldAsk();
    std::printf("TestOverviewWatch OK\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
