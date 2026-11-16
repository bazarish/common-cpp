// Bazarish project (c) 2026
#pragma once

#include <bazarish/Clock.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <optional>

namespace bazarish::client {

inline constexpr std::int64_t kServiceCadenceMs = kSecondsPerHour * kMillisPerSecond;

inline std::optional<std::int64_t> cadencedAtMs(
    const std::optional<std::int64_t> dueAtMs, const std::int64_t lastAttemptMs)
{
    if (!dueAtMs.has_value()) {
        return std::nullopt;
    }
    return lastAttemptMs == 0 ? *dueAtMs : std::max(*dueAtMs, lastAttemptMs + kServiceCadenceMs);
}

inline std::optional<std::int64_t> secondToMs(const std::optional<std::int64_t> atSecond)
{
    return atSecond.has_value() ? std::optional<std::int64_t>(*atSecond * kMillisPerSecond)
                                : std::nullopt;
}

inline std::optional<std::int64_t> atMsAfter(
    const std::int64_t nowMs, const std::optional<std::chrono::milliseconds> wait)
{
    return wait.has_value() ? std::optional<std::int64_t>(nowMs + wait->count()) : std::nullopt;
}

inline std::optional<std::chrono::milliseconds> waitForSoonest(
    const std::int64_t nowMs, const std::initializer_list<std::optional<std::int64_t>> dueAtMs)
{
    std::optional<std::int64_t> soonest;
    for (const std::optional<std::int64_t>& due : dueAtMs) {
        if (due.has_value() && (!soonest.has_value() || *due < *soonest)) {
            soonest = due;
        }
    }
    if (!soonest.has_value()) {
        return std::nullopt;
    }
    return std::chrono::milliseconds(std::max<std::int64_t>(0, *soonest - nowMs));
}

}  // namespace bazarish::client
