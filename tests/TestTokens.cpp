// Bazarish project (c) 2026
#include "bazarish/Tokens.hpp"

#include "bazarish/Bytes.hpp"

#include <cstdio>
#include <cstdlib>
#include <functional>
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

namespace {

const std::string kAlice = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const std::string kBob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

bool throws(const std::function<void()>& what)
{
    try {
        what();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

}  // namespace

int main()
{
    const Bytes secret = randomBytes(kDeliverySecretSize);
    const Bytes other = randomBytes(kDeliverySecretSize);

    // A mask is the account's secret and one correspondent, and nothing else:
    // same pair, same mask; any other pair, another mask.
    const Bytes forAlice = deliveryTokenMask(secret, kAlice);
    CHECK(forAlice.size() == kDeliveryTokenSize);
    CHECK(deliveryTokenMask(secret, kAlice) == forAlice);
    CHECK(deliveryTokenMask(secret, kBob) != forAlice);
    CHECK(deliveryTokenMask(other, kAlice) != forAlice);
    CHECK(throws([&]() { (void)deliveryTokenMask(Bytes{0x01}, kAlice); }));
    CHECK(throws([&]() { (void)deliveryTokenMask(secret, ""); }));

    // A token is the size it always was, and no two are alike.
    const Bytes token = generateDeliveryToken(forAlice);
    CHECK(token.size() == kDeliveryTokenSize);
    CHECK(generateDeliveryToken(forAlice) != token);
    CHECK(throws([&]() { (void)generateDeliveryToken(Bytes{0x01, 0x02}); }));

    // What the revocation sweep asks: minted under this mask, or not.
    const Bytes forBob = deliveryTokenMask(secret, kBob);
    for (int i = 0; i < 64; ++i) {
        CHECK(deliveryTokenMatches(generateDeliveryToken(forAlice), forAlice));
        CHECK(!deliveryTokenMatches(generateDeliveryToken(forBob), forAlice));
    }
    // Nothing else answers yes: a random 32 bytes is not a token of ours.
    for (int i = 0; i < 64; ++i) {
        CHECK(!deliveryTokenMatches(randomBytes(kDeliveryTokenSize), forAlice));
    }
    // A malformed token is not a match, and does not throw at a server sweeping
    // a directory it did not write.
    CHECK(!deliveryTokenMatches(Bytes{0x01}, forAlice));
    CHECK(!deliveryTokenMatches(token, Bytes{0x01}));

    std::fprintf(stderr, "TestTokens passed\n");
    return 0;
}
