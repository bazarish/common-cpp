// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

namespace bazarish {

// One-time delivery tokens: 256-bit random values. The recipient registers
// sha256(token) with its server; a sender presents the token itself inside
// the sealed envelope; the server hashes, looks up and consumes it.
inline constexpr std::size_t kDeliveryTokenSize = 32;

Bytes generateDeliveryToken();
Bytes deliveryTokenHash(const Bytes& token);

}  // namespace bazarish
