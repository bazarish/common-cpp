// Bazarish project (c) 2026
#include "bazarish/I2pAddress.hpp"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
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
    // Golden vector produced by i2pd's own tooling (i2pd-tools keyinfo -b) for a
    // freshly generated Ed25519 destination: the b33 (encrypted-LeaseSet) address
    // must match i2pd's BlindedPublicKey::ToB33 exactly.
    const std::string destination
        = "GmVBArK-6asEg1BTOKbZ9O7c9VFbbm6g4TVPBrmuNyIcD0t-2kEJy39~dawKvPQsNJyTLK5eJi1S8jadM~z"
          "TNEpb5KHKLw6dXxgnWHw2rOVl5MXT7a96ovHhfkiaiSQQc4HIwQJhOg6hwbbhwNNs-QBLA47l5g9008tq1m"
          "Q8mhew8oiNH1ssI6vHdYkE2KdMwk1ppZ15Cyy4qe~sxAhpdvdcrJg~4VGd~flv2Zb3xQRjpcXkIWtSk0b7G"
          "6NOJm0EHXjxMFjA4LaktYebwpl1uOX-s4Qs6NMJOHUZ0JMfNUn8TYgzd70hHjXwyhnPh7Hk~cshRcI5Veh8"
          "tGU7xiEPdYezb6BSV1JalzJ7BHRqVjE6nAnlWDXZnjt1Av9USy1Kh7NvoFJXUlqXMnsEdGpWMTqcCeVYNdm"
          "eO3UC~1RLLUqHs2-gUldSWpcyewR0alYxOpwJ5Vg12Z47dQL~VEstSkf0nWn19OasjC6~ojqwvCfoe9asYV"
          "cikv94jT~PdFrxBQAEAAcAAA==";
    const std::string expectedB33 = "a2pbgr7utvu7l5hgvsgc5p5chkylyj7ipplkyykxekjp66enh7hxiwxr.b32.i2p";

    CHECK(encryptedLeaseSetHost(destination) == expectedB33);

    // A truncated destination is rejected rather than mis-parsed.
    bool threw = false;
    try {
        (void)encryptedLeaseSetHost("AAAA");
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);

    // .b32.i2p validation: the blinded b33 this project publishes is valid, and so
    // is the plain b32 of any destination a peer may still name; raw destinations,
    // addressbook names and malformed labels are not.
    const std::string plainB32 = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
    CHECK(isB32I2pHost(expectedB33));   // 56-char blinded b33
    CHECK(isB32I2pHost(plainB32));      // 52-char plain b32
    CHECK(!isB32I2pHost(destination));  // raw base64 destination
    CHECK(!isB32I2pHost("stats.i2p"));  // short addressbook name (not .b32.i2p)
    CHECK(isB32I2pHost("abc.b32.i2p"));  // length not constrained (b32 vs b33 differ)
    CHECK(!isB32I2pHost(std::string(52, '1') + ".b32.i2p"));  // non-base32 chars
    CHECK(!isB32I2pHost(".b32.i2p"));   // empty label
    CHECK(!isB32I2pHost(""));

    // An uppercased label (I2P b32 is lowercase) is rejected.
    std::string upper = plainB32;
    for (std::size_t i = 0; i + 8 < upper.size(); ++i) {
        if (upper[i] >= 'a' && upper[i] <= 'z') {
            upper[i] = static_cast<char>(upper[i] - 'a' + 'A');
        }
    }
    CHECK(!isB32I2pHost(upper));

    threw = false;
    try {
        validateB32I2pHost("stats.i2p");
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
    validateB32I2pHost(expectedB33);  // does not throw

    std::printf("TestI2pAddress: all checks passed\n");
    return 0;
}
