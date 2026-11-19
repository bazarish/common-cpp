// Bazarish project (c) 2026
#include "PlayoutBuffer.hpp"

#include "TestUtil.hpp"

#include <cstdint>
#include <cstdio>

using namespace bazarish;

namespace {

constexpr std::size_t kTarget = 3;
constexpr std::size_t kLimit = 6;
constexpr std::uint64_t kConceal = 2;
constexpr std::uint64_t kSamples = 100;
constexpr std::uint64_t kCommonGapMs = 20;
constexpr std::uint64_t kTailGapMs = 70;
constexpr std::uint64_t kBeyondLongestMs = 5;

Bytes frameOf(const std::uint64_t sequence)
{
    return Bytes{static_cast<std::uint8_t>(sequence)};
}

bool plays(PlayoutBuffer& buffer, const std::uint64_t sequence)
{
    const PlayoutBuffer::Next next = buffer.take();
    return next.kind == PlayoutBuffer::Kind::eFrame && next.opus == frameOf(sequence);
}

void waitsForTheTargetBeforePlaying()
{
    PlayoutBuffer buffer(kTarget, kLimit, kConceal);
    buffer.put(10, frameOf(10));
    buffer.put(11, frameOf(11));
    CHECK(buffer.take().kind == PlayoutBuffer::Kind::eNothing);
    CHECK(buffer.depth() == 0);
    buffer.put(12, frameOf(12));
    CHECK(plays(buffer, 10));
    CHECK(buffer.depth() == kTarget - 1);
    CHECK(plays(buffer, 11));
    CHECK(plays(buffer, 12));
}

void reordersAndConcealsAShortGap()
{
    PlayoutBuffer buffer(kTarget, kLimit, kConceal);
    buffer.put(2, frameOf(2));
    buffer.put(1, frameOf(1));
    buffer.put(4, frameOf(4));
    CHECK(plays(buffer, 1));
    CHECK(plays(buffer, 2));
    CHECK(buffer.take().kind == PlayoutBuffer::Kind::eLost);
    CHECK(plays(buffer, 4));
}

void skipsAGapLongerThanConcealment()
{
    PlayoutBuffer buffer(kTarget, kLimit, kConceal);
    buffer.put(1, frameOf(1));
    buffer.put(9, frameOf(9));
    buffer.put(10, frameOf(10));
    CHECK(plays(buffer, 1));
    CHECK(plays(buffer, 9));
    CHECK(plays(buffer, 10));
}

void drainedRefillsAndCounts()
{
    PlayoutBuffer buffer(kTarget, kLimit, kConceal);
    for (std::uint64_t sequence = 1; sequence <= kTarget; ++sequence) {
        buffer.put(sequence, frameOf(sequence));
    }
    for (std::uint64_t sequence = 1; sequence <= kTarget; ++sequence) {
        CHECK(plays(buffer, sequence));
    }
    CHECK(buffer.take().kind == PlayoutBuffer::Kind::eNothing);
    CHECK(buffer.counts().underruns == 1);
    buffer.put(4, frameOf(4));
    CHECK(buffer.take().kind == PlayoutBuffer::Kind::eNothing);
    buffer.put(5, frameOf(5));
    buffer.put(6, frameOf(6));
    CHECK(plays(buffer, 4));
}

void lateAndOverflowAreCounted()
{
    PlayoutBuffer buffer(kTarget, kLimit, kConceal);
    for (std::uint64_t sequence = 1; sequence <= kLimit + 2; ++sequence) {
        buffer.put(sequence, frameOf(sequence));
    }
    CHECK(buffer.counts().dropped == 2);
    CHECK(plays(buffer, 3));
    buffer.put(2, frameOf(2));
    CHECK(buffer.counts().late == 1);
}

void histogramSummarises()
{
    GapHistogram gaps;
    for (std::uint64_t i = 0; i + 2 < kSamples; ++i) {
        gaps.add(kCommonGapMs);
    }
    gaps.add(kTailGapMs);
    gaps.add(GapHistogram::kLongestMs + kBeyondLongestMs);
    const GapHistogram::Summary summary = gaps.summary();
    CHECK(summary.samples == kSamples);
    CHECK(summary.medianMs == kCommonGapMs);
    CHECK(summary.p99Ms == kTailGapMs);
    CHECK(summary.maxMs == GapHistogram::kLongestMs + kBeyondLongestMs);
}

}  // namespace

int main()
try {
    waitsForTheTargetBeforePlaying();
    reordersAndConcealsAShortGap();
    skipsAGapLongerThanConcealment();
    drainedRefillsAndCounts();
    lateAndOverflowAreCounted();
    histogramSummarises();
    std::fprintf(stderr, "TestPlayoutBuffer passed\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
