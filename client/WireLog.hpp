// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish::client {

struct WireEvent {
    std::int64_t atMillis = 0;
    bool outgoing = true;
    std::string what;
    std::string status;
    std::string detail;
};

inline constexpr std::size_t kWireLogCapacity = 100;

class WireLog {
public:
    void record(WireEvent event);
    std::vector<WireEvent> snapshot() const;
    void clear();

private:
    mutable std::mutex mutex_;
    std::deque<WireEvent> events_;
};

}  // namespace bazarish::client
