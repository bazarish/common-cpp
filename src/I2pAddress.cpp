// Bazarish project (c) 2026
#include "bazarish/I2pAddress.hpp"

#include "bazarish/Bytes.hpp"

#include <zlib.h>

#include <array>
#include <cstdint>
#include <stdexcept>

namespace {

// I2P-base64 is the standard alphabet with '+' -> '-' and '/' -> '~'.
std::string i2pToStandardBase64(const std::string& text)
{
    std::string out = text;
    for (char& c : out) {
        if (c == '-') {
            c = '+';
        } else if (c == '~') {
            c = '/';
        }
    }
    return out;
}

// KeysAndCert layout: 256-byte encryption-key field + 128-byte signing-key
// field + certificate.
constexpr std::size_t kEncryptionFieldLen = 256;
constexpr std::size_t kSigningFieldLen = 128;
constexpr std::size_t kCertOffset = kEncryptionFieldLen + kSigningFieldLen;  // 384
constexpr std::size_t kEd25519KeyLen = 32;
constexpr std::uint8_t kCertTypeKey = 5;
constexpr std::uint8_t kSigTypeEd25519 = 7;
constexpr std::uint8_t kBlindedSigTypeEd25519 = 11;  // RedDSA-SHA512-Ed25519

}  // namespace

namespace bazarish {

std::string encryptedLeaseSetHost(const std::string& samBase64Destination)
{
    const Bytes destination = fromBase64(i2pToStandardBase64(samBase64Destination));

    // Need the full key fields plus a 7-byte key certificate.
    if (destination.size() < kCertOffset + 7) {
        throw std::runtime_error("i2p destination too short");
    }
    // Key certificate: type(1) | length(2) | sigType(2, big-endian) | encType(2).
    if (destination[kCertOffset] != kCertTypeKey) {
        throw std::runtime_error("i2p destination is not a key certificate");
    }
    const unsigned sigType
        = (static_cast<unsigned>(destination[kCertOffset + 3]) << 8) | destination[kCertOffset + 4];
    if (sigType != kSigTypeEd25519) {
        throw std::runtime_error("only Ed25519 i2p destinations are supported");
    }

    // The 32-byte Ed25519 signing key sits in the last bytes of the 128-byte
    // signing-key field.
    const std::size_t keyOffset = kCertOffset - kEd25519KeyLen;  // 352

    std::array<std::uint8_t, 3 + kEd25519KeyLen> addr{};
    addr[0] = 0;  // flags (no per-client auth)
    addr[1] = kSigTypeEd25519;
    addr[2] = kBlindedSigTypeEd25519;
    for (std::size_t i = 0; i < kEd25519KeyLen; ++i) {
        addr[3 + i] = destination[keyOffset + i];
    }

    // CRC-32 (zlib) over the signing key, little-endian, XORed into the prefix.
    const uLong checksum = crc32(0L, addr.data() + 3, kEd25519KeyLen);
    addr[0] ^= static_cast<std::uint8_t>(checksum);
    addr[1] ^= static_cast<std::uint8_t>(checksum >> 8);
    addr[2] ^= static_cast<std::uint8_t>(checksum >> 16);

    return toBase32(Bytes(addr.begin(), addr.end())) + ".b32.i2p";
}

}  // namespace bazarish
