// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <string>

namespace bazarish {

inline constexpr std::size_t kDeliveryPassSize = 32;
inline constexpr std::size_t kDeliverySecretSize = 32;

Bytes deliveryPass(const Bytes& deliverySecret, const std::string& peerFingerprint);

Bytes deliveryPassHandle(const Bytes& pass);

}  // namespace bazarish
