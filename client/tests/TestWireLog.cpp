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
            CHECK(event.what.rfind("line ", 0) == 0);
            CHECK(event.status == "200");
            CHECK(event.atMillis > 0);
        }
    }
    stop.store(true);
    writer.join();
    CHECK(log.snapshot().size() <= kWireLogCapacity);
}

}  // namespace

int main()
{
    testRingKeepsTheNewest();
    testConcurrentRecordAndSnapshot();
    std::printf("TestWireLog: all checks passed\n");
    return 0;
}
