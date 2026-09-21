// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <ctime>

namespace bazarish {

// Wall-clock seconds. Every timestamp in the protocol - signatures, card issue
// dates, delegation terms, sweep deadlines - is unix seconds, and this is the
// one place they are read.
//
// An operation reads it once and passes the value down. Two independent reads in
// one chain can land either side of a boundary, and then a record is chosen for
// one day and signed for another.
inline std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

inline constexpr std::int64_t kSecondsPerMinute = 60;
inline constexpr std::int64_t kSecondsPerHour = 60 * kSecondsPerMinute;
inline constexpr std::int64_t kSecondsPerDay = 24 * kSecondsPerHour;

}  // namespace bazarish
