// Bazarish project (c) 2026
#include "bazarish/Padding.hpp"

#include <cstdio>
#include <cstdlib>
#include <set>
#include <stdexcept>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;

int main()
{
    // Everything that fits under a step comes out at that step, so what an
    // observer measures counts steps rather than bytes.
    std::set<std::size_t> sizes;
    for (std::size_t length = 0; length <= kPaddingLadder[0] - kLengthPrefixBytes; ++length) {
        const Bytes padded = padToLadder(Bytes(length, 0x41));
        sizes.insert(padded.size());
        CHECK(unpadFromLadder(padded) == Bytes(length, 0x41));
    }
    CHECK(sizes.size() == 1);
    CHECK(*sizes.begin() == kPaddingLadder[0]);

    // Each step is reached exactly at its own boundary, prefix included.
    for (const std::size_t step : kPaddingLadder) {
        CHECK(padToLadder(Bytes(step - kLengthPrefixBytes, 0x42)).size() == step);
        CHECK(padToLadder(Bytes(step - kLengthPrefixBytes + 1, 0x42)).size() > step);
    }

    // Past the top step it is a whole multiple of it, so a large payload is
    // still quantised rather than measured.
    const std::size_t top = kPaddingLadder[std::size(kPaddingLadder) - 1];
    for (std::size_t length = top; length < top * 3; length += top / 4) {
        const Bytes padded = padToLadder(Bytes(length, 0x43));
        CHECK(padded.size() % top == 0);
        CHECK(unpadFromLadder(padded).size() == length);
    }

    // A ceiling stops a payload being rounded past what the protocol will
    // accept: it is prefixed and left at its own length instead.
    {
        constexpr std::size_t kCeiling = 4096;
        const Bytes big(kCeiling, 0x44);
        const Bytes padded = padToLadder(big, kCeiling);
        CHECK(padded.size() == big.size() + kLengthPrefixBytes);
        CHECK(unpadFromLadder(padded) == big);
        // Under the ceiling nothing changes.
        CHECK(padToLadder(Bytes(10, 0x45), kCeiling).size() == kPaddingLadder[0]);
    }

    // What the prefix says is what comes back, and a prefix that lies is refused
    // rather than trusted.
    {
        bool threw = false;
        try {
            unpadFromLadder(Bytes{0x00, 0x00});
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
        threw = false;
        try {
            Bytes lying = padToLadder(Bytes(8, 0x46));
            lying[3] = 0xFF;  // claims more content than the block holds
            unpadFromLadder(lying);
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
    }

    std::printf("TestPadding: ok\n");
    return 0;
}
