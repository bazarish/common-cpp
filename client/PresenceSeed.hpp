// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::client {

inline constexpr std::size_t kPresenceSeedBytes = 32;
inline constexpr std::int64_t kPresenceHorizonDays = 14;
inline constexpr std::int64_t kPresenceRefreshBelowDays = 7;
// Each side of midnight UTC: the old and the new day's addresses both stand this long.
inline constexpr std::int64_t kPresenceHalfOverlapSeconds = 300;

// Days since the Unix epoch, UTC.
using PresenceDay = std::int64_t;

using UtcClock = std::function<std::int64_t()>;
std::int64_t systemUtcSeconds();

PresenceDay presenceDayOf(std::int64_t unixSeconds);
std::int64_t presenceDayStart(PresenceDay day);
// "YYYYMMDD".
std::string presenceDayText(PresenceDay day);
PresenceDay presenceDayFromText(const std::string& text);

class PresenceSeed {
public:
    static PresenceSeed generate();
    explicit PresenceSeed(Bytes seed);
    PresenceSeed(const PresenceSeed&) = default;
    PresenceSeed(PresenceSeed&&) noexcept = default;
    PresenceSeed& operator=(const PresenceSeed&) = default;
    PresenceSeed& operator=(PresenceSeed&&) noexcept = default;
    ~PresenceSeed();

    const Bytes& bytes() const { return seed_; }
    i2p::Keys destFor(PresenceDay day) const;
    std::string hostFor(PresenceDay day) const;
    Key readerFor(PresenceDay day) const;

private:
    Bytes seed_;
};

struct ScheduledDay {
    PresenceDay day = 0;
    std::string dest;
    Bytes reader;

    bool operator==(const ScheduledDay&) const = default;
};

using PresenceSchedule = std::vector<ScheduledDay>;

PresenceSchedule presenceScheduleFrom(
    const PresenceSeed& seed, PresenceDay first, std::int64_t days = kPresenceHorizonDays);

nlohmann::json presenceScheduleJson(const PresenceSchedule& schedule);
PresenceSchedule presenceScheduleFromJson(const nlohmann::json& days);
PresenceSchedule offeredPresenceSchedule(const nlohmann::json& days, PresenceDay today);

PresenceSchedule trimmedSchedule(PresenceSchedule schedule, PresenceDay today);
PresenceSchedule mergedSchedule(
    const PresenceSchedule& held, const PresenceSchedule& offered, PresenceDay today);
std::optional<ScheduledDay> scheduledOn(const PresenceSchedule& schedule, PresenceDay day);

}  // namespace bazarish::client
