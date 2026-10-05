// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstddef>
#include <string>

namespace bazarish {

std::string encryptedLeaseSetHost(const std::string& i2pBase64Destination);

bool isB32I2pHost(const std::string& host);

// I2P's base64 alphabet is the standard one with '+' as '-' and '/' as '~'.
std::string i2pToStandardBase64(const std::string& text);
std::string standardToI2pBase64(const std::string& text);

std::size_t i2pIdentityLength(const Bytes& buffer);

void validateB32I2pHost(const std::string& host);

}  // namespace bazarish
