// Bazarish project (c) 2026
#pragma once

#include <condition_variable>
#include <mutex>
#include <stop_token>

namespace bazarish {

// libc++ 18 does not wake a stop_token wait of condition_variable_any on request_stop.
class StopWake {
public:
    StopWake(const std::stop_token& stop, std::mutex& mutex, std::condition_variable_any& cv)
        : wake_(stop, Wake{mutex, cv})
    {
    }

private:
    struct Wake {
        std::mutex& mutex;
        std::condition_variable_any& cv;

        void operator()() const
        {
            {
                const std::lock_guard<std::mutex> lock(mutex);
            }
            cv.notify_all();
        }
    };

    std::stop_callback<Wake> wake_;
};

}  // namespace bazarish
