// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace bazarish {

using Bytes = std::vector<unsigned char>;

// Hex, lowercase.
std::string toHex(const Bytes& data);
Bytes fromHex(const std::string& text);

// Base32 per RFC 4648, lowercase, no padding. Used for fingerprints.
std::string toBase32(const Bytes& data);
Bytes fromBase32(const std::string& text);

// Base64, standard alphabet with padding. Used for binary fields in JSON.
std::string toBase64(const Bytes& data);
Bytes fromBase64(const std::string& text);

// Base64url (RFC 4648 §5): URL-safe alphabet ('+'->'-', '/'->'_'), no padding,
// so the blob rides inside a URI with no percent-encoding.
std::string toBase64Url(const Bytes& data);
Bytes fromBase64Url(const std::string& text);

// Cryptographically secure random bytes (OpenSSL RAND).
Bytes randomBytes(std::size_t count);

}  // namespace bazarish
