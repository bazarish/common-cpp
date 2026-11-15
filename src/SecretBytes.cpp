// Bazarish project (c) 2026
#include "bazarish/SecretBytes.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace bazarish {

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";
constexpr std::size_t kHexPerByte = 2;
constexpr unsigned kNibbleBits = 4;
constexpr unsigned char kNibbleMask = 0x0f;
// RFC 4648: three bytes become four characters.
constexpr std::size_t kBase64GroupBytes = 3;
constexpr std::size_t kBase64GroupChars = 4;

}  // namespace

SecretBytes::SecretBytes(Bytes bytes)
    : bytes_(std::move(bytes))
{
}

SecretBytes::SecretBytes(const std::size_t size)
    : bytes_(size)
{
}

SecretBytes::SecretBytes(const SecretBytes& other)
    : bytes_(other.bytes_)
{
}

SecretBytes::SecretBytes(SecretBytes&& other) noexcept
    : bytes_(std::move(other.bytes_))
{
    other.bytes_.clear();
}

SecretBytes& SecretBytes::operator=(const SecretBytes& other)
{
    if (this != &other) {
        clear();
        bytes_ = other.bytes_;
    }
    return *this;
}

SecretBytes& SecretBytes::operator=(SecretBytes&& other) noexcept
{
    if (this != &other) {
        clear();
        bytes_ = std::move(other.bytes_);
        other.bytes_.clear();
    }
    return *this;
}

SecretBytes::~SecretBytes()
{
    wipe();
}

const Bytes& SecretBytes::bytes() const
{
    return bytes_;
}

unsigned char* SecretBytes::data()
{
    return bytes_.data();
}

std::size_t SecretBytes::size() const
{
    return bytes_.size();
}

bool SecretBytes::empty() const
{
    return bytes_.empty();
}

void SecretBytes::resize(const std::size_t size)
{
    if (size > bytes_.size()) {
        throw std::logic_error("a secret only shrinks in place, so no copy of it is left behind");
    }
    OPENSSL_cleanse(bytes_.data() + size, bytes_.size() - size);
    bytes_.resize(size);
}

void SecretBytes::wipe()
{
    if (!bytes_.empty()) {
        OPENSSL_cleanse(bytes_.data(), bytes_.size());
    }
}

void SecretBytes::clear()
{
    wipe();
    bytes_.clear();
}

void SecretBytes::append(const ByteView more)
{
    SecretBytes grown(bytes_.size() + more.size());
    std::copy(bytes_.begin(), bytes_.end(), grown.data());
    std::copy(more.begin(), more.end(), grown.data() + bytes_.size());
    *this = std::move(grown);
}

Bytes SecretBytes::release()
{
    Bytes released = std::move(bytes_);
    bytes_.clear();
    return released;
}

bool SecretBytes::operator==(const SecretBytes& other) const
{
    return bytes_.size() == other.bytes_.size()
        && CRYPTO_memcmp(bytes_.data(), other.bytes_.data(), bytes_.size()) == 0;
}

SecretBytes secretBase64(const ByteView data)
{
    if (data.empty()) {
        return {};
    }
    SecretBytes encoded((data.size() + kBase64GroupBytes - 1) / kBase64GroupBytes * kBase64GroupChars + 1);
    const int written = EVP_EncodeBlock(encoded.data(), data.data(), static_cast<int>(data.size()));
    if (written < 0 || static_cast<std::size_t>(written) + 1 != encoded.size()) {
        throw std::runtime_error("base64 encoding failed");
    }
    encoded.resize(static_cast<std::size_t>(written));
    return encoded;
}

SecretBytes secretHexLine(const SecretBytes& secret, const std::string& tail)
{
    SecretBytes line(secret.size() * kHexPerByte + tail.size());
    unsigned char* at = line.data();
    for (const unsigned char byte : secret.bytes()) {
        *at++ = static_cast<unsigned char>(kHexDigits[byte >> kNibbleBits]);
        *at++ = static_cast<unsigned char>(kHexDigits[byte & kNibbleMask]);
    }
    std::copy(tail.begin(), tail.end(), at);
    return line;
}

}  // namespace bazarish
