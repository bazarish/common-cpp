// Bazarish project (c) 2026
#include "WireLog.hpp"

#include <chrono>
#include <utility>

namespace bazarish::client {

namespace {

std::int64_t nowMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

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
