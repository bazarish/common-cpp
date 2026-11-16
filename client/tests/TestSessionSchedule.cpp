// Bazarish project (c) 2026
#include "AccountManager.hpp"
#include "PresenceSeed.hpp"
#include "ServiceSchedule.hpp"
#include "Session.hpp"

#include <bazarish/Epochs.hpp>

#include "TestUtil.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>

using namespace bazarish;
using namespace bazarish::client;

namespace {

namespace fs = std::filesystem;

constexpr std::chrono::hours kEpochCreationSpread{1};

std::int64_t secondsOf(const std::chrono::milliseconds wait)
{
    return std::chrono::duration_cast<std::chrono::seconds>(wait).count();
}

void checkWaitsForTheEarliestDeadline(const fs::path& dir)
{
    AccountManager manager(dir / "accounts");
    const AccountInfo made = manager.create("Scheduled", AccountKind::eUser, "pw");
    const std::unique_ptr<Session> session = manager.open(made.id, "pw");
    std::atomic<std::int64_t> utc{systemUtcSeconds()};
    const UtcClock clock = [&utc]() { return utc.load(); };
    session->setEpochClock(clock);
    session->setPresenceClock(clock);

    const std::optional<std::chrono::milliseconds> unchecked = session->untilNextDue();
    CHECK(unchecked.has_value() && *unchecked == std::chrono::milliseconds::zero());

    session->flushPendingEchoes();
    const std::optional<std::chrono::milliseconds> rested = session->untilNextDue();
    CHECK(rested.has_value() && *rested > std::chrono::milliseconds::zero());
    const std::int64_t untilTomorrow = presenceDayStart(presenceDayOf(utc.load()) + 1) - utc.load();
    CHECK(secondsOf(*rested) <= untilTomorrow);

    const EpochNumber last = session->ownEpochs().back().n;
    if (secondsOf(*rested) < untilTomorrow) {
        CHECK(secondsOf(*rested) == epochStart(last) + 1 - utc.load());
    }

    utc = epochStart(last) + 1;
    session->flushPendingEchoes();
    const std::optional<std::chrono::milliseconds> keyDue = session->untilNextDue();
    CHECK(keyDue.has_value());
    CHECK(*keyDue <= kEpochCreationSpread);
    if (session->ownEpochs().back().n != last) {
        CHECK(*keyDue > std::chrono::milliseconds::zero());
        return;
    }

    const std::int64_t keyAt = utc.load() + secondsOf(*keyDue);
    utc = keyAt - 1;
    session->flushPendingEchoes();
    CHECK(session->ownEpochs().back().n == last);
    const std::optional<std::chrono::milliseconds> oneSecond = session->untilNextDue();
    CHECK(oneSecond.has_value() && *oneSecond == std::chrono::seconds(1));

    utc = keyAt;
    session->flushPendingEchoes();
    CHECK(session->ownEpochs().back().n == last + 1);
    const std::optional<std::chrono::milliseconds> after = session->untilNextDue();
    CHECK(after.has_value() && *after > std::chrono::milliseconds::zero());
}

void checkSwitchedOffWaitsOnlyForKeyErasure(const fs::path& dir)
{
    AccountManager manager(dir / "off");
    const AccountInfo made = manager.create("Off", AccountKind::eUser, "pw");
    const std::unique_ptr<Session> session = manager.open(made.id, "pw");
    const std::int64_t now = systemUtcSeconds();
    session->setEpochClock([now]() { return now; });
    session->setSwitchedOff(true);
    session->flushPendingEchoes();
    const std::optional<std::chrono::milliseconds> wait = session->untilNextDue();
    CHECK(wait.has_value());
    const EpochNumber first = session->ownEpochs().front().n;
    CHECK(secondsOf(*wait) == epochEnd(first) + kEpochKeptAfterEndSeconds - now);
}

void checkSoonestDutyWins()
{
    constexpr std::int64_t kNowMs = 1'000'000;
    constexpr std::int64_t kSoonMs = 5'000;
    constexpr std::int64_t kLaterMs = 9'000;
    CHECK(!waitForSoonest(kNowMs, {std::nullopt, std::nullopt}).has_value());
    CHECK(waitForSoonest(kNowMs, {kNowMs + kLaterMs, std::nullopt, kNowMs + kSoonMs})
        == std::chrono::milliseconds(kSoonMs));
    CHECK(waitForSoonest(kNowMs, {kNowMs - kSoonMs}) == std::chrono::milliseconds::zero());
    CHECK(atMsAfter(kNowMs, std::chrono::milliseconds(kSoonMs)) == kNowMs + kSoonMs);
    CHECK(!atMsAfter(kNowMs, std::nullopt).has_value());
}

void checkFailedAttemptWaitsTheCadence()
{
    constexpr std::int64_t kNowMs = 1'000'000;
    CHECK(!cadencedAtMs(std::nullopt, kNowMs).has_value());
    CHECK(cadencedAtMs(kNowMs, 0) == kNowMs);
    CHECK(cadencedAtMs(kNowMs, kNowMs) == kNowMs + kServiceCadenceMs);
    CHECK(cadencedAtMs(kNowMs + 2 * kServiceCadenceMs, kNowMs) == kNowMs + 2 * kServiceCadenceMs);
    CHECK(secondToMs(kSecondsPerDay) == kSecondsPerDay * kMillisPerSecond);
    CHECK(kServiceCadenceMs == std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::hours(1)).count());
}

}  // namespace

int main()
try {
    checkSoonestDutyWins();
    checkFailedAttemptWaitsTheCadence();
    const testutil::ScratchDir scratch("session-schedule");
    const fs::path& dir = scratch.path();
    checkWaitsForTheEarliestDeadline(dir);
    checkSwitchedOffWaitsOnlyForKeyErasure(dir);
    std::printf("TestSessionSchedule: all checks passed\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
