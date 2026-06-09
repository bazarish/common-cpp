// Bazarish project (c) 2026
#include "bazarish/Tokens.hpp"

#include "bazarish/Crypto.hpp"

#include <stdexcept>

namespace bazarish {

Bytes generateDeliveryToken()
{
    return randomBytes(kDeliveryTokenSize);
}

Bytes deliveryTokenHash(const Bytes& token)
{
    if (token.size() != kDeliveryTokenSize) {
        throw std::invalid_argument("delivery token has wrong size");
    }
    return sha256(token);
}

}  // namespace bazarish
