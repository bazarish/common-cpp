// Bazarish project (c) 2026
#include "bazarish/Restart.hpp"

#include <chrono>
#include <utility>

namespace bazarish {

namespace {

// How long the answer is given to reach the caller before the service stops
// under it. The panel is on the other end of that response and turns it into
// "restarting"; a stop that races it would look like a failure instead.
constexpr std::chrono::milliseconds kResponseGrace{300};

}  // namespace

RestartSwitch::RestartSwitch(std::function<void()> stop)
    : stop_(std::move(stop))
{
    waiter_ = std::thread([this]() {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this]() { return asked_ || releasing_; });
            if (!asked_) {
                return;
            }
        }
        std::this_thread::sleep_for(kResponseGrace);
        if (stop_) {
            stop_();
        }
    });
}

RestartSwitch::~RestartSwitch()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        releasing_ = true;
    }
    cv_.notify_all();
    if (waiter_.joinable()) {
        waiter_.join();
    }
}

void RestartSwitch::request()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        asked_ = true;
    }
    cv_.notify_all();
}

bool RestartSwitch::requested() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return asked_;
}

}  // namespace bazarish
