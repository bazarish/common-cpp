// Bazarish project (c) 2026
#pragma once

#include <charconv>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace bazarish {

// docs-main api/ClientApi.md, Held requests.
inline constexpr const char* kHeldWaitKey = "wait";
inline constexpr std::int64_t kHeldWaitMinSeconds = 60;
inline constexpr std::int64_t kHeldWaitMaxSeconds = 300;

inline std::optional<std::chrono::seconds> heldWaitOf(const std::string& text)
{
    if (text.empty()) {
        return std::chrono::seconds(kHeldWaitMaxSeconds);
    }
    std::int64_t seconds = 0;
    const char* const end = text.data() + text.size();
    const auto [stop, error] = std::from_chars(text.data(), end, seconds);
    if (error != std::errc() || stop != end || seconds < kHeldWaitMinSeconds
        || seconds > kHeldWaitMaxSeconds) {
        return std::nullopt;
    }
    return std::chrono::seconds(seconds);
}

inline std::string heldWaitRefusal()
{
    return "a held request names a hold of " + std::to_string(kHeldWaitMinSeconds) + " to "
        + std::to_string(kHeldWaitMaxSeconds) + " seconds";
}

}  // namespace bazarish
