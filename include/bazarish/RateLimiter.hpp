// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish {

// Rate-limits inbound work by who it came from, where "who" is whatever the
// transport can name and the caller cannot forge: an I2P destination. A fixed
// window per caller - at most maxPerWindow in windowSeconds - which is enough
// against a flood and cheap enough to sit in front of every request.
//
// Accountability is per-destination rather than per-signature on purpose: a
// signature says who signed, not who is spending the service's time, and the
// thing being defended is the time.
class RateLimiter {
public:
    RateLimiter(std::size_t maxPerWindow, std::int64_t windowSeconds);

    // Records an attempt from `caller` at `now` and returns whether it is within
    // the limit (false -> drop without serving). An empty caller is always
    // allowed: a transport that cannot name its peer has nothing to limit by,
    // and refusing there would refuse everything.
    bool allow(const std::string& caller, std::int64_t now);

private:
    struct Window {
        std::int64_t start = 0;
        std::size_t count = 0;
    };

    const std::size_t maxPerWindow_;
    const std::int64_t windowSeconds_;
    std::mutex mutex_;
    std::unordered_map<std::string, Window> windows_;
};

}  // namespace bazarish
