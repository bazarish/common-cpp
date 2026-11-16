// Bazarish project (c) 2026
#include "WireLog.hpp"

#include "TestUtil.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish::client;

namespace {

WireEvent lineFor(const int number)
{
    WireEvent event;
    event.what = "line " + std::to_string(number);
    event.status = "200";
    return event;
}

void testRingKeepsTheNewest()
{
    WireLog log;
    const int extra = 25;
    for (int i = 0; i < static_cast<int>(kWireLogCapacity) + extra; ++i) {
        log.record(lineFor(i));
    }
    const std::vector<WireEvent> events = log.snapshot();
    CHECK(events.size() == kWireLogCapacity);
    CHECK(events.front().what == "line " + std::to_string(extra));
    CHECK(events.back().what
        == "line " + std::to_string(static_cast<int>(kWireLogCapacity) + extra - 1));
    CHECK(events.front().atMillis > 0);

    log.clear();
    CHECK(log.snapshot().empty());
}

void testConcurrentRecordAndSnapshot()
{
    WireLog log;
    std::atomic<bool> stop{false};
    std::thread writer([&log, &stop]() {
        for (int i = 0; !stop.load(); ++i) {
            log.record(lineFor(i));
        }
    });
    for (int round = 0; round < 200; ++round) {
        for (const WireEvent& event : log.snapshot()) {
            CHECK(event.what.starts_with("line "));
            CHECK(event.status == "200");
            CHECK(event.atMillis > 0);
        }
    }
    stop.store(true);
    writer.join();
    CHECK(log.snapshot().size() <= kWireLogCapacity);
}

void testListenerHearsEachEntry()
{
    WireLog log;
    log.record(lineFor(0));
    std::vector<WireEvent> heard;
    const std::vector<WireEvent> held
        = log.watch([&heard](const WireEvent& event) { heard.push_back(event); });
    CHECK(held.size() == 1);
    CHECK(held.front().what == "line 0");
    CHECK(heard.empty());

    log.record(lineFor(1));
    log.record(lineFor(2));
    CHECK(heard.size() == 2);
    CHECK(heard.front().what == "line 1");
    CHECK(heard.back().what == "line 2");
    CHECK(heard.back().atMillis > 0);

    log.unwatch();
    log.record(lineFor(3));
    CHECK(heard.size() == 2);
}

}  // namespace

int main()
try {
    testRingKeepsTheNewest();
    testConcurrentRecordAndSnapshot();
    testListenerHearsEachEntry();
    std::printf("TestWireLog: all checks passed\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
