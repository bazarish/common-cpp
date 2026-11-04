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
}

std::vector<WireEvent> WireLog::snapshot() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<WireEvent>(events_.begin(), events_.end());
}

void WireLog::clear()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    events_.clear();
}

}  // namespace bazarish::client
