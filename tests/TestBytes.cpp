// Bazarish project (c) 2026
#include "bazarish/Bytes.hpp"
#include "bazarish/Percent.hpp"

#include "TestUtil.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>

using namespace bazarish;

int main()
{
    constexpr std::uint64_t kSides = 6;
    constexpr int kThrows = 6000;
    std::array<int, kSides> seen{};
    for (int i = 0; i < kThrows; ++i) {
        const std::uint64_t side = randomBelow(kSides);
        CHECK(side < kSides);
        ++seen[side];
    }
    for (const int count : seen) {
        CHECK(count > 0);
    }
    CHECK(randomBelow(0) == 0);
    CHECK(randomBelow(1) == 0);

    const Bytes data = {0x00, 0x01, 0xab, 0xff};
    CHECK(toHex(data) == "0001abff");
    CHECK(fromHex("0001abff") == data);
    CHECK(fromHex("0001ABFF") == data);
    CHECK_THROWS(fromHex("abc"));
    CHECK_THROWS(fromHex("zz"));

    // RFC 4648 vectors, lowercase and unpadded.
    const Bytes foobar = {'f', 'o', 'o', 'b', 'a', 'r'};
    CHECK(toBase32(foobar) == "mzxw6ytboi");
    CHECK(toBase32(Bytes{'f'}) == "my");
    CHECK(toBase32({}) == "");

    CHECK(toBase32(Bytes(32, 0x42)).size() == 52);

    // Base64 round trip.
    const Bytes hello = {'h', 'e', 'l', 'l', 'o'};
    CHECK(toBase64(hello) == "aGVsbG8=");
    CHECK(fromBase64("aGVsbG8=") == hello);
    CHECK(toBase64({}) == "");
    CHECK(fromBase64("") == Bytes{});
    CHECK_THROWS(fromBase64("abc"));

    const Bytes a = randomBytes(32);
    const Bytes b = randomBytes(32);
    CHECK(a.size() == 32);
    CHECK(a != b);

    constexpr int kDraws = 200;
    CHECK(randomBetween(7, 7) == 7);
    CHECK(randomBetween(9, 3) == 9);
    bool sawLow = false;
    bool sawHigh = false;
    for (int i = 0; i < kDraws; ++i) {
        const std::uint64_t drawn = randomBetween(4, 6);
        CHECK(drawn >= 4 && drawn <= 6);
        sawLow = sawLow || drawn == 4;
        sawHigh = sawHigh || drawn == 6;
    }
    CHECK(sawLow && sawHigh);

    CHECK(percentEncode("a b/c?d=e&f~g") == "a%20b%2Fc%3Fd%3De%26f~g");
    CHECK(percentEncode("\xD0\xB4") == "%D0%B4");
    CHECK(percentDecode("%D0%B4%2f") == "\xD0\xB4/");
    CHECK(percentDecode("50%") == "50%");
    CHECK(percentDecode("a%4") == "a%4");
    CHECK(percentDecode("%zz") == "%zz");
    CHECK(percentDecode("a+b") == "a+b");
    CHECK(formDecode("a+b%2Bc") == "a b+c");
    const std::string every = "\x01 !\"#$%&'()*+,-./09:;<=>?@AZ[\\]^_`az{|}~\x7F\xFF";
    CHECK(percentDecode(percentEncode(every)) == every);

    return 0;
}
