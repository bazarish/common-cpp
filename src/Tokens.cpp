// Bazarish project (c) 2026
#include "bazarish/Tokens.hpp"

#include "bazarish/Crypto.hpp"

#include <stdexcept>

namespace bazarish {

namespace {

// Where the mark sits inside a token: at the end, so the random part in front of
// it is what a token is made of.
constexpr std::size_t markOffset()
{
    return kDeliveryTokenSize - kDeliveryTokenMarkSize;
}

}  // namespace

Bytes deliveryTokenMask(const Bytes& deliverySecret, const std::string& peerFingerprint)
{
    if (deliverySecret.size() != kDeliverySecretSize) {
        throw std::invalid_argument("delivery secret has wrong size");
    }
    if (peerFingerprint.empty()) {
        throw std::invalid_argument("a delivery mask needs a correspondent");
    }
    Bytes material = deliverySecret;
    material.insert(material.end(), peerFingerprint.begin(), peerFingerprint.end());
    return sha256(material);
}

Bytes generateDeliveryToken(const Bytes& mask)
{
    if (mask.size() != kDeliveryTokenSize) {
        throw std::invalid_argument("delivery mask has wrong size");
    }
    Bytes token = randomBytes(markOffset());
    token.insert(token.end(), kDeliveryTokenMark, kDeliveryTokenMark + kDeliveryTokenMarkSize);
    for (std::size_t i = 0; i < kDeliveryTokenSize; ++i) {
        token[i] ^= mask[i];
    }
    return token;
}

bool deliveryTokenMatches(const Bytes& token, const Bytes& mask)
{
    if (token.size() != kDeliveryTokenSize || mask.size() != kDeliveryTokenSize) {
        return false;
    }
    for (std::size_t i = 0; i < kDeliveryTokenMarkSize; ++i) {
        const std::size_t at = markOffset() + i;
        if ((token[at] ^ mask[at]) != static_cast<std::uint8_t>(kDeliveryTokenMark[i])) {
            return false;
        }
    }
    return true;
}

}  // namespace bazarish
