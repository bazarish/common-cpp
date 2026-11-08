// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bazarish {

using Bytes = std::vector<unsigned char>;
using ByteView = std::span<const unsigned char>;
using ByteBuffer = std::span<unsigned char>;

ByteView viewOf(std::string_view text);

// Network byte order: the field's whole width holds the value, most significant byte first.
void putBigEndian(ByteBuffer field, std::uint64_t value);
std::uint64_t getBigEndian(ByteView field);
void appendBigEndian(Bytes& out, std::uint64_t value, std::size_t width);
ByteBuffer bufferOf(std::string& text);

std::string toHex(const Bytes& data);
// The value of one hex digit, either case; -1 for anything else.
int hexDigitValue(char c);
Bytes fromHex(const std::string& text);

// Base32 per RFC 4648, lowercase, no padding.
std::string toBase32(const Bytes& data);

// Base64, standard alphabet with padding.
std::string toBase64(const Bytes& data);
Bytes fromBase64(const std::string& text);

std::string toBase64Url(const Bytes& data);
Bytes fromBase64Url(const std::string& text);

// Cryptographically secure random bytes (OpenSSL RAND).
Bytes randomBytes(std::size_t count);
// Uniform in [0, bound); 0 when bound is 0.
std::uint64_t randomBelow(std::uint64_t bound);
// Uniform in [low, high]; low when high is below it.
std::uint64_t randomBetween(std::uint64_t low, std::uint64_t high);

}  // namespace bazarish
