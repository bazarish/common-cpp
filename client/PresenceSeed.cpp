// Bazarish project (c) 2026
#include "PresenceSeed.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/I2pAddress.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <chrono>
#include <format>
#include <stdexcept>
#include <utility>

namespace bazarish::client {

namespace {

// docs-main Presence.md: the HKDF-SHA256 info strings, each followed by "|YYYYMMDD".
constexpr char kDestSigningInfo[] = "bazarish presence dest v1|";
constexpr char kDestCryptoInfo[] = "bazarish presence dest crypto v1|";
constexpr char kReaderInfo[] = "bazarish presence reader v1|";
constexpr std::size_t kDerivedKeyBytes = 32;
constexpr std::size_t kReaderBytes = 32;
constexpr std::size_t kDayTextLength = 8;
constexpr char kDayField[] = "d";
constexpr char kDestField[] = "dest";
constexpr char kReaderField[] = "reader";
constexpr std::size_t kDayFields = 3;

Bytes derived(const Bytes& seed, const char* const info, const PresenceDay day)
{
    return hkdfSha256(seed, {}, info + presenceDayText(day), kDerivedKeyBytes);
}

void cleanse(Bytes& secret)
{
    if (!secret.empty()) {
        OPENSSL_cleanse(secret.data(), secret.size());
    }
}

ScheduledDay scheduledDayFromJson(const nlohmann::json& entry)
{
    if (!entry.is_object() || entry.size() != kDayFields) {
        throw std::invalid_argument("a scheduled day names its day, address and reader key");
    }
    ScheduledDay scheduled;
    scheduled.day = presenceDayFromText(entry.at(kDayField).get<std::string>());
    scheduled.dest = entry.at(kDestField).get<std::string>();
    if (!isB33I2pHost(scheduled.dest)) {
        throw std::invalid_argument("a presence address is a b33 host");
    }
    scheduled.reader = fromBase64(entry.at(kReaderField).get<std::string>());
    if (scheduled.reader.size() != kReaderBytes) {
        throw std::invalid_argument("a presence reader key is 32 bytes");
    }
    return scheduled;
}

}  // namespace

std::int64_t systemUtcSeconds()
{
    return nowSeconds();
}

PresenceDay presenceDayOf(const std::int64_t unixSeconds)
{
    const std::int64_t day = unixSeconds / kSecondsPerDay;
    return unixSeconds % kSecondsPerDay < 0 ? day - 1 : day;
}

std::int64_t presenceDayStart(const PresenceDay day)
{
    return day * kSecondsPerDay;
}

std::string presenceDayText(const PresenceDay day)
{
    const std::chrono::year_month_day date{std::chrono::sys_days{std::chrono::days{day}}};
    return std::format("{:04}{:02}{:02}", static_cast<int>(date.year()),
        static_cast<unsigned>(date.month()), static_cast<unsigned>(date.day()));
}

PresenceDay presenceDayFromText(const std::string& text)
{
    if (text.size() != kDayTextLength
        || !std::all_of(text.begin(), text.end(), [](const char c) { return c >= '0' && c <= '9'; })) {
        throw std::invalid_argument("a day is written YYYYMMDD");
    }
    constexpr std::size_t kYearDigits = 4;
    constexpr std::size_t kMonthDigits = 2;
    const std::chrono::year_month_day date{std::chrono::year{std::stoi(text.substr(0, kYearDigits))},
        std::chrono::month{static_cast<unsigned>(std::stoi(text.substr(kYearDigits, kMonthDigits)))},
        std::chrono::day{static_cast<unsigned>(std::stoi(text.substr(kYearDigits + kMonthDigits)))}};
    if (!date.ok()) {
        throw std::invalid_argument("no such day: " + text);
    }
    return std::chrono::sys_days{date}.time_since_epoch().count();
}

PresenceSeed PresenceSeed::generate()
{
    return PresenceSeed(randomBytes(kPresenceSeedBytes));
}

PresenceSeed::PresenceSeed(Bytes seed)
    : seed_(std::move(seed))
{
    if (seed_.size() != kPresenceSeedBytes) {
        cleanse(seed_);
        throw std::invalid_argument("a presence seed is 32 bytes");
    }
}

PresenceSeed::~PresenceSeed()
{
    cleanse(seed_);
}

i2p::Keys PresenceSeed::destFor(const PresenceDay day) const
{
    Bytes signing = derived(seed_, kDestSigningInfo, day);
    Bytes crypto = derived(seed_, kDestCryptoInfo, day);
    i2p::Keys keys = i2p::Keys::fromSeeds(signing, crypto);
    cleanse(signing);
    cleanse(crypto);
    return keys;
}

std::string PresenceSeed::hostFor(const PresenceDay day) const
{
    return i2p::routingHost(destFor(day).publicBase64());
}

Key PresenceSeed::readerFor(const PresenceDay day) const
{
    Bytes raw = derived(seed_, kReaderInfo, day);
    Key reader = Key::fromRawX25519Private(raw);
    cleanse(raw);
    return reader;
}

PresenceSchedule presenceScheduleFrom(
    const PresenceSeed& seed, const PresenceDay first, const std::int64_t days)
{
    PresenceSchedule schedule;
    for (PresenceDay day = first; day < first + days; ++day) {
        schedule.push_back({day, seed.hostFor(day), seed.readerFor(day).rawPublic()});
    }
    return schedule;
}

nlohmann::json presenceScheduleJson(const PresenceSchedule& schedule)
{
    nlohmann::json days = nlohmann::json::array();
    for (const ScheduledDay& scheduled : schedule) {
        days.push_back({{kDayField, presenceDayText(scheduled.day)}, {kDestField, scheduled.dest},
            {kReaderField, toBase64(scheduled.reader)}});
    }
    return days;
}

PresenceSchedule presenceScheduleFromJson(const nlohmann::json& days)
{
    if (!days.is_array()) {
        throw std::invalid_argument("a presence schedule is a list of days");
    }
    if (days.size() > static_cast<std::size_t>(kPresenceHorizonDays)) {
        throw std::invalid_argument("a presence schedule reaches past the horizon");
    }
    PresenceSchedule schedule;
    for (const nlohmann::json& entry : days) {
        ScheduledDay scheduled = scheduledDayFromJson(entry);
        if (!schedule.empty() && scheduled.day != schedule.back().day + 1) {
            throw std::invalid_argument("a presence schedule skips or repeats a day");
        }
        schedule.push_back(std::move(scheduled));
    }
    return schedule;
}

PresenceSchedule offeredPresenceSchedule(const nlohmann::json& days, const PresenceDay today)
{
    PresenceSchedule schedule = presenceScheduleFromJson(days);
    if (schedule.empty()) {
        throw std::invalid_argument("an offered presence schedule names at least one day");
    }
    if (schedule.front().day < today - 1) {
        throw std::invalid_argument("an offered presence schedule starts before yesterday");
    }
    return schedule;
}

PresenceSchedule trimmedSchedule(PresenceSchedule schedule, const PresenceDay today)
{
    std::erase_if(schedule, [today](const ScheduledDay& scheduled) { return scheduled.day < today; });
    return schedule;
}

PresenceSchedule mergedSchedule(
    const PresenceSchedule& held, const PresenceSchedule& offered, const PresenceDay today)
{
    const bool replaces
        = held.empty() || (!offered.empty() && offered.front().day >= held.front().day);
    return trimmedSchedule(replaces ? offered : held, today);
}

std::optional<ScheduledDay> scheduledOn(const PresenceSchedule& schedule, const PresenceDay day)
{
    const auto found = std::find_if(schedule.begin(), schedule.end(),
        [day](const ScheduledDay& scheduled) { return scheduled.day == day; });
    if (found == schedule.end()) {
        return std::nullopt;
    }
    return *found;
}

}  // namespace bazarish::client
