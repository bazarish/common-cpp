// Bazarish project (c) 2026
#include "bazarish/ResolvePuzzle.hpp"

#include "TestUtil.hpp"

#include <cstdint>

using namespace bazarish;

namespace {

constexpr std::uint32_t kTestBits = 6;
constexpr std::size_t kStampBytes = 24;
constexpr unsigned kThreads = 2;
constexpr std::uint64_t kAttempts = 64;

}  // namespace

int main()
{
    const Bytes stamp(kStampBytes, 0x21);
    const Bytes otherStamp(kStampBytes, 0x22);

    CHECK(puzzleSolved(stamp, 0, 0));
    CHECK_THROWS(puzzleSolved(stamp, 0, kMaxPuzzleBits + 1));
    CHECK_THROWS(solvePuzzle(stamp, kMaxPuzzleBits + 1, kThreads));

    const std::uint64_t nonce = solvePuzzle(stamp, kTestBits, kThreads);
    CHECK(puzzleSolved(stamp, nonce, kTestBits));

    std::uint64_t failures = 0;
    for (std::uint64_t tried = 0; tried < kAttempts; ++tried) {
        failures += puzzleSolved(otherStamp, nonce + tried, kTestBits) ? 0 : 1;
    }
    // A wrong answer passes with odds of 2^-bits, so most of these fail.
    CHECK(failures > kAttempts / 2);
    return 0;
}
