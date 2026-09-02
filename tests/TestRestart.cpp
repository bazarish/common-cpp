// Bazarish project (c) 2026
#include <bazarish/Restart.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;

int main()
{
    // Nobody asked: the switch releases its thread and the service is never
    // stopped under it.
    {
        std::atomic<int> stops{0};
        {
            RestartSwitch restart([&stops]() { stops.fetch_add(1); });
            CHECK(!restart.requested());
        }
        CHECK(stops.load() == 0);
    }

    // Asked from a handler: the call returns at once - the response still has to
    // be written - and the stop happens afterwards, on the switch's own thread.
    {
        std::atomic<int> stops{0};
        std::atomic<bool> stoppedByAnotherThread{false};
        const std::thread::id handler = std::this_thread::get_id();
        {
            RestartSwitch restart([&]() {
                stoppedByAnotherThread.store(std::this_thread::get_id() != handler);
                stops.fetch_add(1);
            });
            restart.request();
            CHECK(restart.requested());
            // Still on the handler's thread, and the service is still up.
            CHECK(stops.load() == 0);
        }  // the destructor waits for the switch's thread
        CHECK(stops.load() == 1);
        CHECK(stoppedByAnotherThread.load());
    }

    // Asking twice stops once: a panel that double-clicks does not stop the
    // service, then stop it again as it comes back up.
    {
        std::atomic<int> stops{0};
        {
            RestartSwitch restart([&stops]() { stops.fetch_add(1); });
            restart.request();
            restart.request();
            restart.request();
        }
        CHECK(stops.load() == 1);
    }

    std::printf("TestRestart: all checks passed\n");
    return 0;
}
