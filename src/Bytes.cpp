// Bazarish project (c) 2026
#include "bazarish/Bytes.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdexcept>

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";
constexpr char kBase32Digits[] = "abcdefghijklmnopqrstuvwxyz234567";

int hexValue(const char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int base32Value(const char c)
{
    if (c >= 'a' && c <= 'z') {
        return c - 'a';
    }
    if (c >= '2' && c <= '7') {
        return c - '2' + 26;
    }
    return -1;
}

}  // namespace

namespace bazarish {

std::string toHex(const Bytes& data)
{
    std::string out;
    out.reserve(data.size() * 2);
    for (const unsigned char byte : data) {
        out.push_back(kHexDigits[byte >> 4]);
        out.push_back(kHexDigits[byte & 0x0f]);
    }
    return out;
}

Bytes fromHex(const std::string& text)
{
    if (text.size() % 2 != 0) {
        throw std::invalid_argument("hex string has odd length");
    }
    Bytes out;
    out.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const int high = hexValue(text[i]);
        const int low = hexValue(text[i + 1]);
        if (high < 0 || low < 0) {
            throw std::invalid_argument("invalid hex character");
        }
        out.push_back(static_cast<unsigned char>((high << 4) | low));
    }
    return out;
}

std::string toBase32(const Bytes& data)
{
    std::string out;
    out.reserve((data.size() * 8 + 4) / 5);
    unsigned int buffer = 0;
    int bits = 0;
    for (const unsigned char byte : data) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kBase32Digits[(buffer >> bits) & 0x1f]);
        }
    }
    if (bits > 0) {
        out.push_back(kBase32Digits[(buffer << (5 - bits)) & 0x1f]);
    }
    return out;
}

Bytes fromBase32(const std::string& text)
{
    Bytes out;
    out.reserve(text.size() * 5 / 8);
    unsigned int buffer = 0;
    int bits = 0;
    for (const char c : text) {
        const int value = base32Value(c);
        if (value < 0) {
            throw std::invalid_argument("invalid base32 character");
        }
        buffer = (buffer << 5) | static_cast<unsigned int>(value);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<unsigned char>((buffer >> bits) & 0xff));
        }
    }
    // Leftover bits are padding produced by the encoder; they must be zero.
    if (bits > 0 && (buffer & ((1u << bits) - 1)) != 0) {
        throw std::invalid_argument("invalid base32 trailing bits");
    }
    return out;
}

std::string toBase64(const Bytes& data)
{
    if (data.empty()) {
        return {};
    }
    std::string out;
    out.resize(((data.size() + 2) / 3) * 4);
    const int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(out.data()), data.data(), static_cast<int>(data.size()));
    if (written < 0 || static_cast<std::size_t>(written) != out.size()) {
        throw std::runtime_error("base64 encoding failed");
    }
    return out;
}

Bytes fromBase64(const std::string& text)
{
    if (text.empty()) {
        return {};
    }
    if (text.size() % 4 != 0) {
        throw std::invalid_argument("base64 string length is not a multiple of 4");
    }
    Bytes out(text.size() / 4 * 3);
    const int written = EVP_DecodeBlock(
        out.data(), reinterpret_cast<const unsigned char*>(text.data()),
        static_cast<int>(text.size()));
    if (written < 0) {
        throw std::invalid_argument("invalid base64 input");
    }
    // EVP_DecodeBlock does not account for '=' padding; trim it manually.
    std::size_t padding = 0;
    if (text.size() >= 2 && text[text.size() - 1] == '=') {
        padding = text[text.size() - 2] == '=' ? 2 : 1;
    }
    out.resize(static_cast<std::size_t>(written) - padding);
    return out;
}

std::string toBase64Url(const Bytes& data)
{
    std::string text = toBase64(data);
    for (char& c : text) {
        if (c == '+') {
            c = '-';
        } else if (c == '/') {
            c = '_';
        }
    }
    while (!text.empty() && text.back() == '=') {
        text.pop_back();
    }
    return text;
}

Bytes fromBase64Url(const std::string& text)
{
    std::string standard = text;
    for (char& c : standard) {
        if (c == '-') {
            c = '+';
        } else if (c == '_') {
            c = '/';
        }
    }
    while (standard.size() % 4 != 0) {
        standard.push_back('=');
    }
    return fromBase64(standard);
}

Bytes randomBytes(const std::size_t count)
{
    Bytes out(count);
    if (count > 0 && RAND_bytes(out.data(), static_cast<int>(count)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return out;
}

}  // namespace bazarish
