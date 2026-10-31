// Bazarish project (c) 2026
#include "bazarish/Bytes.hpp"

#include "TestUtil.hpp"

#include <stdexcept>

using namespace bazarish;

int main()
{
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

    return 0;
}
