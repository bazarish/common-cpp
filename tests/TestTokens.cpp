// Bazarish project (c) 2026
#include "bazarish/Tokens.hpp"

#include "bazarish/Crypto.hpp"

#include "TestUtil.hpp"

#include <stdexcept>

using namespace bazarish;

int main()
{
    const Bytes token = generateDeliveryToken();
    CHECK(token.size() == kDeliveryTokenSize);

    // Tokens are random.
    CHECK(generateDeliveryToken() != token);

    // The hash matches a direct SHA-256 and is deterministic.
    const Bytes hash = deliveryTokenHash(token);
    CHECK(hash == sha256(token));
    CHECK(deliveryTokenHash(token) == hash);

    // Wrong-size input is rejected.
    CHECK_THROWS(deliveryTokenHash(Bytes{0x01, 0x02}));

    return 0;
}
