// Bazarish project (c) 2026
#include "WireLog.hpp"

#include <bazarish/Clock.hpp>

#include <utility>

namespace bazarish::client {

void WireLog::record(WireEvent event)
{
    if (event.atMillis == 0) {
        event.atMillis = nowMillis();
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back(std::move(event));
    while (events_.size() > kWireLogCapacity) {
        events_.pop_front();
    }
    if (listener_) {
        listener_(events_.back());
    }
}

std::vector<WireEvent> WireLog::snapshot() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<WireEvent>(events_.begin(), events_.end());
}

std::vector<WireEvent> WireLog::watch(Listener listener)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    listener_ = std::move(listener);
    return std::vector<WireEvent>(events_.begin(), events_.end());
}

void WireLog::unwatch()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    listener_ = nullptr;
}

void WireLog::clear()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    events_.clear();
}

}  // namespace bazarish::client
