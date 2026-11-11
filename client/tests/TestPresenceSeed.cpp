// Bazarish project (c) 2026
#include "PresenceSeed.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/I2pAddress.hpp>

#include "TestUtil.hpp"

#include <cstdio>
#include <set>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

namespace {

// 2026-11-11 00:00:00 UTC.
constexpr std::int64_t kMidnight = 1794355200;
constexpr PresenceDay kToday = kMidnight / kSecondsPerDay;
constexpr std::int64_t kNoon = kMidnight + kSecondsPerDay / 2;
constexpr std::size_t kRawKeyBytes = 32;
// What every device derives from this seed for 2026-11-11; the reader was checked outside OpenSSL.
const std::string kKnownSeed = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
const std::string kKnownHost = "cm5ywilwxiki35hnyhyum54xjmsyasujrmtw5zpnra6c7bdhxpvhxg5r.b32.i2p";
const std::string kKnownReader = "199452f7ccdd6b016965c6bd8f5e30781254167fbd43f66087afaea7b13d463d";

}  // namespace

int main()
{
    CHECK(presenceDayOf(kMidnight) == kToday);
    CHECK(presenceDayOf(kMidnight - 1) == kToday - 1);
    CHECK(presenceDayOf(kNoon) == kToday);
    CHECK(presenceDayStart(kToday) == kMidnight);
    CHECK(presenceDayText(kToday) == "20261111");
    CHECK(presenceDayFromText("20261111") == kToday);
    CHECK(presenceDayText(presenceDayFromText("20280229")) == "20280229");
    CHECK_THROWS(presenceDayFromText("20270229"));
    CHECK_THROWS(presenceDayFromText("2026111"));
    CHECK_THROWS(presenceDayFromText("2026-1-11"));

    {
        const PresenceSeed known(fromHex(kKnownSeed));
        CHECK(known.hostFor(kToday) == kKnownHost);
        CHECK(toHex(known.readerFor(kToday).rawPublic()) == kKnownReader);
    }

    const Bytes seedBytes = randomBytes(kPresenceSeedBytes);
    const PresenceSeed seed(seedBytes);
    const PresenceSeed sameSeed(seedBytes);
    const PresenceSeed otherSeed = PresenceSeed::generate();
    CHECK_THROWS(PresenceSeed(randomBytes(kPresenceSeedBytes - 1)));

    CHECK(seed.destFor(kToday).blob() == sameSeed.destFor(kToday).blob());
    CHECK(seed.readerFor(kToday).rawPrivate() == sameSeed.readerFor(kToday).rawPrivate());
    CHECK(seed.hostFor(kToday) == sameSeed.hostFor(kToday));

    std::set<std::string> hosts;
    std::set<std::string> readers;
    for (PresenceDay day = kToday; day < kToday + kPresenceHorizonDays; ++day) {
        const std::string host = seed.hostFor(day);
        CHECK(isB33I2pHost(host));
        hosts.insert(host);
        hosts.insert(otherSeed.hostFor(day));
        const Key reader = seed.readerFor(day);
        CHECK(reader.isA(kClassicalSealingAlgorithm));
        CHECK(!reader.hasKem());
        CHECK(reader.rawPublic().size() == kRawKeyBytes);
        readers.insert(toHex(reader.rawPrivate()));
        readers.insert(toHex(otherSeed.readerFor(day).rawPrivate()));
    }
    CHECK(hosts.size() == 2 * kPresenceHorizonDays);
    CHECK(readers.size() == 2 * kPresenceHorizonDays);
    CHECK(seed.destFor(kToday).blob() != seed.destFor(kToday + 1).blob());

    {
        const i2p::Keys master = seed.destFor(kToday);
        CHECK(!master.isOffline());
        const i2p::Keys delegated = master.issueTransient(1);
        CHECK(delegated.isOffline());
        CHECK(i2p::routingHost(delegated.publicBase64()) == seed.hostFor(kToday));
    }

    const PresenceSchedule schedule = presenceScheduleFrom(seed, kToday);
    CHECK(schedule.size() == static_cast<std::size_t>(kPresenceHorizonDays));
    CHECK(schedule.front().day == kToday);
    CHECK(schedule.front().dest == seed.hostFor(kToday));
    CHECK(schedule.front().reader == seed.readerFor(kToday).rawPublic());
    CHECK(schedule.back().day == kToday + kPresenceHorizonDays - 1);
    CHECK(presenceScheduleFrom(sameSeed, kToday) == schedule);

    const nlohmann::json wire = presenceScheduleJson(schedule);
    CHECK(wire.front().at("d") == "20261111");
    CHECK(presenceScheduleFromJson(wire) == schedule);
    CHECK(offeredPresenceSchedule(wire, kToday) == schedule);
    CHECK(offeredPresenceSchedule(wire, kToday + 1) == schedule);
    CHECK_THROWS(offeredPresenceSchedule(wire, kToday + 2));
    CHECK_THROWS(offeredPresenceSchedule(nlohmann::json::array(), kToday));
    CHECK(presenceScheduleFromJson(nlohmann::json::array()).empty());
    {
        nlohmann::json gap = wire;
        gap.erase(gap.begin() + 1);
        CHECK_THROWS(presenceScheduleFromJson(gap));
        nlohmann::json repeat = wire;
        repeat[1] = repeat[0];
        CHECK_THROWS(presenceScheduleFromJson(repeat));
        nlohmann::json tooLong = presenceScheduleJson(
            presenceScheduleFrom(seed, kToday, kPresenceHorizonDays + 1));
        CHECK_THROWS(presenceScheduleFromJson(tooLong));
        nlohmann::json plainB32 = wire;
        plainB32[0]["dest"] = std::string(52, 'a') + ".b32.i2p";
        CHECK_THROWS(presenceScheduleFromJson(plainB32));
        nlohmann::json shortReader = wire;
        shortReader[0]["reader"] = toBase64(randomBytes(kRawKeyBytes - 1));
        CHECK_THROWS(presenceScheduleFromJson(shortReader));
        nlohmann::json extraField = wire;
        extraField[0]["note"] = "x";
        CHECK_THROWS(presenceScheduleFromJson(extraField));
        nlohmann::json badDay = wire;
        badDay[0]["d"] = "2026-11-11";
        CHECK_THROWS(presenceScheduleFromJson(badDay));
        CHECK_THROWS(presenceScheduleFromJson(nlohmann::json::object()));
    }

    {
        const PresenceSchedule later = presenceScheduleFrom(seed, kToday + 3);
        CHECK(mergedSchedule(schedule, later, kToday) == later);
        CHECK(mergedSchedule(later, schedule, kToday) == later);
        CHECK(mergedSchedule({}, schedule, kToday) == schedule);
        const PresenceSchedule trimmed = mergedSchedule(schedule, schedule, kToday + 2);
        CHECK(trimmed.size() == static_cast<std::size_t>(kPresenceHorizonDays - 2));
        CHECK(trimmed.front().day == kToday + 2);
        CHECK(trimmedSchedule(schedule, kToday + kPresenceHorizonDays).empty());
        CHECK(scheduledOn(schedule, kToday + 1).has_value());
        CHECK(scheduledOn(schedule, kToday + 1)->dest == seed.hostFor(kToday + 1));
        CHECK(!scheduledOn(schedule, kToday + kPresenceHorizonDays).has_value());
    }

    std::fprintf(stderr, "TestPresenceSeed passed\n");
    return 0;
}
