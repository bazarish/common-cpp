// Bazarish project (c) 2026
#include "bazarish/Padding.hpp"

#include <algorithm>
#include <climits>
#include <cstdint>
#include <iterator>
#include <stdexcept>

namespace bazarish {

std::size_t paddedSize(const std::size_t length)
{
    for (const std::size_t step : kPaddingLadder) {
        if (length <= step) {
            return step;
        }
    }
    const std::size_t largest = kPaddingLadder[std::size(kPaddingLadder) - 1];
    return ((length + largest - 1) / largest) * largest;
}

namespace {

std::size_t paddedTotal(const std::size_t payload, const std::size_t ceiling)
{
    const std::size_t prefixed = payload + kLengthPrefixBytes;
    const std::size_t stepped = paddedSize(prefixed);
    return (ceiling > 0 && stepped > ceiling) ? prefixed : stepped;
}

void padInto(const Bytes& payload, unsigned char* const padded)
{
    const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
    for (std::size_t i = 0; i < kLengthPrefixBytes; ++i) {
        const unsigned shift = static_cast<unsigned>((kLengthPrefixBytes - 1 - i) * CHAR_BIT);
        padded[i] = static_cast<std::uint8_t>(length >> shift);
    }
    std::copy(payload.begin(), payload.end(), padded + kLengthPrefixBytes);
}

std::size_t paddedLength(const Bytes& padded)
{
    if (padded.size() < kLengthPrefixBytes) {
        throw std::runtime_error("padded payload is too short to hold its own length");
    }
    std::size_t length = 0;
    for (std::size_t i = 0; i < kLengthPrefixBytes; ++i) {
        length = (length << CHAR_BIT) | padded[i];
    }
    if (length > padded.size() - kLengthPrefixBytes) {
        throw std::runtime_error("padded payload is shorter than its length says");
    }
    return length;
}

}  // namespace

Bytes padToLadder(const Bytes& payload, const std::size_t ceiling)
{
    Bytes padded(paddedTotal(payload.size(), ceiling), 0);
    padInto(payload, padded.data());
    return padded;
}

Bytes unpadFromLadder(const Bytes& padded)
{
    const std::size_t length = paddedLength(padded);
    return Bytes(padded.begin() + kLengthPrefixBytes,
        padded.begin() + kLengthPrefixBytes + static_cast<std::ptrdiff_t>(length));
}

SecretBytes padToLadder(const SecretBytes& payload, const std::size_t ceiling)
{
    SecretBytes padded(paddedTotal(payload.size(), ceiling));
    padInto(payload.bytes(), padded.data());
    return padded;
}

SecretBytes unpadFromLadder(const SecretBytes& padded)
{
    const std::size_t length = paddedLength(padded.bytes());
    SecretBytes payload(length);
    const auto from = padded.bytes().begin() + kLengthPrefixBytes;
    std::copy(from, from + static_cast<std::ptrdiff_t>(length), payload.data());
    return payload;
}

}  // namespace bazarish
