// Bazarish project (c) 2026
#include "bazarish/I2pAddress.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/I2p.hpp"

#include <zlib.h>

#include <array>
#include <climits>
#include <cstdint>
#include <stdexcept>

namespace {

constexpr std::size_t kEncryptionFieldLen = 256;
constexpr std::size_t kSigningFieldLen = 128;
constexpr std::size_t kCertOffset = kEncryptionFieldLen + kSigningFieldLen;
constexpr std::size_t kEd25519KeyLen = 32;
constexpr std::size_t kCertHeaderLen = 3;
constexpr std::uint8_t kCertTypeKey = 5;
constexpr std::uint8_t kSigTypeEd25519 = 7;
constexpr std::uint8_t kBlindedSigTypeEd25519 = 11;

constexpr char kB32Suffix[] = ".b32.i2p";
constexpr std::size_t kB32SuffixLen = sizeof(kB32Suffix) - 1;
constexpr std::size_t kBase32BitsPerChar = 5;
constexpr std::size_t kBlindedHeaderLen = 3;
constexpr std::size_t kDestHashLen = 32;

constexpr std::size_t base32Chars(const std::size_t bytes)
{
    return (bytes * CHAR_BIT + kBase32BitsPerChar - 1) / kBase32BitsPerChar;
}

constexpr std::size_t kB32LabelChars = base32Chars(kDestHashLen);
constexpr std::size_t kB33LabelChars = base32Chars(kBlindedHeaderLen + kEd25519KeyLen);

static_assert(kB32LabelChars == 52);
static_assert(kB33LabelChars == 56);

}  // namespace

namespace bazarish {

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

std::string standardToI2pBase64(const std::string& text)
{
    std::string out = text;
    for (char& c : out) {
        if (c == '+') {
            c = '-';
        } else if (c == '/') {
            c = '~';
        }
    }
    return out;
}

std::size_t i2pIdentityLength(const Bytes& buffer)
{
    if (buffer.size() < kCertOffset + kCertHeaderLen) {
        throw std::runtime_error("i2p identity too short");
    }
    const std::size_t certLen
        = (static_cast<std::size_t>(buffer[kCertOffset + 1]) << 8) | buffer[kCertOffset + 2];
    const std::size_t length = kCertOffset + kCertHeaderLen + certLen;
    if (buffer.size() < length) {
        throw std::runtime_error("i2p identity truncated");
    }
    return length;
}

namespace i2p {

std::string routingHost(const std::string& publicBase64)
{
    return encryptedLeaseSetHost(publicBase64);
}

}  // namespace i2p

std::string encryptedLeaseSetHost(const std::string& i2pBase64Destination)
{
    const Bytes destination = fromBase64(i2pToStandardBase64(i2pBase64Destination));

    if (destination.size() < kCertOffset + 7) {
        throw std::runtime_error("i2p destination too short");
    }
    if (destination[kCertOffset] != kCertTypeKey) {
        throw std::runtime_error("i2p destination is not a key certificate");
    }
    const unsigned sigType
        = (static_cast<unsigned>(destination[kCertOffset + 3]) << 8) | destination[kCertOffset + 4];
    if (sigType != kSigTypeEd25519) {
        throw std::runtime_error("only Ed25519 i2p destinations are supported");
    }

    const std::size_t keyOffset = kCertOffset - kEd25519KeyLen;

    std::array<std::uint8_t, 3 + kEd25519KeyLen> addr{};
    addr[0] = 0;
    addr[1] = kSigTypeEd25519;
    addr[2] = kBlindedSigTypeEd25519;
    for (std::size_t i = 0; i < kEd25519KeyLen; ++i) {
        addr[3 + i] = destination[keyOffset + i];
    }

    const uLong checksum = crc32(0L, addr.data() + 3, kEd25519KeyLen);
    addr[0] ^= static_cast<std::uint8_t>(checksum);
    addr[1] ^= static_cast<std::uint8_t>(checksum >> 8);
    addr[2] ^= static_cast<std::uint8_t>(checksum >> 16);

    return toBase32(Bytes(addr.begin(), addr.end())) + ".b32.i2p";
}

bool isB32I2pHost(const std::string& host)
{
    if (host.size() <= kB32SuffixLen) {
        return false;
    }
    if (host.compare(host.size() - kB32SuffixLen, kB32SuffixLen, kB32Suffix) != 0) {
        return false;
    }
    const std::size_t labelLen = host.size() - kB32SuffixLen;
    if (labelLen != kB32LabelChars && labelLen != kB33LabelChars) {
        return false;
    }
    for (std::size_t i = 0; i < labelLen; ++i) {
        const char c = host[i];
        const bool isBase32Char = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!isBase32Char) {
            return false;
        }
    }
    return true;
}

void validateB32I2pHost(const std::string& host)
{
    if (!isB32I2pHost(host)) {
        throw std::invalid_argument("invalid i2p address (must be a .b32.i2p host): " + host);
    }
}

}  // namespace bazarish
