// Bazarish project (c) 2026
#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>

namespace bazarish {

inline std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

inline std::int64_t nowMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

inline constexpr std::int64_t kSecondsPerMinute = 60;
inline constexpr std::int64_t kSecondsPerHour = 60 * kSecondsPerMinute;
inline constexpr std::int64_t kSecondsPerDay = 24 * kSecondsPerHour;

}  // namespace bazarish
