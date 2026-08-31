// Bazarish project (c) 2026
#include "WireLog.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish::client;

namespace {

WireEvent lineFor(const int number)
{
    WireEvent event;
    event.what = "line " + std::to_string(number);
    event.status = "200";
    return event;
}

// The window shows the tail: what fits is the newest, in the order it happened.
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
    // Recording stamps the time when the caller did not.
    CHECK(events.front().atMillis > 0);

    log.clear();
    CHECK(log.snapshot().empty());
}

// Events arrive from the courier's threads, the sync thread and the network
// thread while the window reads: neither side may see half of one.
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
    // How many the writer got in is its own business; the cap is not.
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
