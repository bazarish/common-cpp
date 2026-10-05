// Bazarish project (c) 2026
#pragma once

#include <string>

namespace bazarish::service {

// HMAC-SHA256(key, data) as a lowercase hex string (OpenSSL EVP_MAC).
std::string hmacSha256Hex(const std::string& key, const std::string& data);

bool constantTimeEqual(const std::string& a, const std::string& b);

}  // namespace bazarish::service
