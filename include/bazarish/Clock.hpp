// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <ctime>

namespace bazarish {

inline std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

inline constexpr std::int64_t kSecondsPerMinute = 60;
inline constexpr std::int64_t kSecondsPerHour = 60 * kSecondsPerMinute;
inline constexpr std::int64_t kSecondsPerDay = 24 * kSecondsPerHour;

}  // namespace bazarish
