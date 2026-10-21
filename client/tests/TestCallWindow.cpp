// Bazarish project (c) 2026
#include "Session.hpp"

#include "TestUtil.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>

using namespace bazarish::client;

namespace {

constexpr std::int64_t kSentAt = 1'800'000'000'000;
constexpr std::int64_t kDeliveryMs = 25'000;
constexpr std::int64_t kClockBehindMs = 40'000;

void inTimeRingsForWhatIsLeft()
{
    const std::optional<std::int64_t> answerBy
        = callAnswerDeadline(kSentAt, kSentAt + kDeliveryMs);
    CHECK(answerBy.has_value());
    CHECK(*answerBy == kSentAt + kCallAnswerWindowMs);
}

void lateOrUndatedIsDropped()
{
    CHECK(!callAnswerDeadline(kSentAt, kSentAt + kCallAnswerWindowMs).has_value());
    CHECK(!callAnswerDeadline(kSentAt, kSentAt + kCallAnswerWindowMs + 1).has_value());
    CHECK(callAnswerDeadline(kSentAt, kSentAt + kCallAnswerWindowMs - 1).has_value());
    CHECK(!callAnswerDeadline(0, kSentAt).has_value());
}

void aClockBehindTheCallerDoesNotLengthenTheRing()
{
    const std::int64_t arrivedAt = kSentAt - kClockBehindMs;
    const std::optional<std::int64_t> answerBy = callAnswerDeadline(kSentAt, arrivedAt);
    CHECK(answerBy.has_value());
    CHECK(*answerBy == arrivedAt + kCallAnswerWindowMs);
}

}  // namespace

int main()
{
    inTimeRingsForWhatIsLeft();
    lateOrUndatedIsDropped();
    aClockBehindTheCallerDoesNotLengthenTheRing();
    std::printf("TestCallWindow: ok\n");
    return 0;
}
