// Bazarish project (c) 2026
#include "bazarish/Padding.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <set>
#include <stdexcept>
#include <string>

using namespace bazarish;

int main()
{
    std::set<std::size_t> sizes;
    for (std::size_t length = 0; length <= kPaddingLadder[0] - kLengthPrefixBytes; ++length) {
        const Bytes padded = padToLadder(Bytes(length, 0x41));
        sizes.insert(padded.size());
        CHECK(unpadFromLadder(padded) == Bytes(length, 0x41));
    }
    CHECK(sizes.size() == 1);
    CHECK(*sizes.begin() == kPaddingLadder[0]);

    for (const std::size_t step : kPaddingLadder) {
        CHECK(padToLadder(Bytes(step - kLengthPrefixBytes, 0x42)).size() == step);
        CHECK(padToLadder(Bytes(step - kLengthPrefixBytes + 1, 0x42)).size() > step);
    }

    const std::size_t top = kPaddingLadder[std::size(kPaddingLadder) - 1];
    for (std::size_t length = top; length < top * 3; length += top / 4) {
        const Bytes padded = padToLadder(Bytes(length, 0x43));
        CHECK(padded.size() % top == 0);
        CHECK(unpadFromLadder(padded).size() == length);
    }

    {
        constexpr std::size_t kCeiling = 4096;
        const Bytes big(kCeiling, 0x44);
        const Bytes padded = padToLadder(big, kCeiling);
        CHECK(padded.size() == big.size() + kLengthPrefixBytes);
        CHECK(unpadFromLadder(padded) == big);
        CHECK(padToLadder(Bytes(10, 0x45), kCeiling).size() == kPaddingLadder[0]);
    }

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
            lying[3] = 0xFF;
            unpadFromLadder(lying);
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
    }

    std::printf("TestPadding: ok\n");
    return 0;
}
