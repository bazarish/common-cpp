// Bazarish project (c) 2026
#include "bazarish/ServerDescriptor.hpp"

#include "bazarish/Crypto.hpp"

#include <stdexcept>

namespace {

constexpr char kPrefix[] = "bazarish://server?";
constexpr std::size_t kPrefixLen = sizeof(kPrefix) - 1;

// A fingerprint is base32(sha256(...)) - kFingerprintTextLength lowercase
// RFC-4648 base32 characters.
bool isFingerprint(const std::string& fingerprint)
{
    if (fingerprint.size() != bazarish::kFingerprintTextLength) {
        return false;
    }
    for (const char c : fingerprint) {
        const bool isBase32Char = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!isBase32Char) {
            return false;
        }
    }
    return true;
}

}  // namespace

namespace bazarish {

std::string encodeServerDescriptor(const ServerDescriptor& descriptor)
{
    std::string uri = std::string(kPrefix) + "v=1&fp=" + descriptor.fingerprint;
    for (const std::string& facade : descriptor.facades) {
        uri += "&facade=" + facade;
    }
    return uri;
}

ServerDescriptor parseServerDescriptor(const std::string& uri)
{
    if (uri.size() <= kPrefixLen || uri.compare(0, kPrefixLen, kPrefix) != 0) {
        throw std::invalid_argument("not a bazarish://server descriptor");
    }

    // The values are URL-safe by construction (base32 fingerprint, plain facade
    // URLs), so a split on '&' and '=' needs no percent-decoding.
    ServerDescriptor descriptor;
    std::string version;
    bool haveVersion = false;
    bool haveFingerprint = false;

    const std::string query = uri.substr(kPrefixLen);
    std::size_t pos = 0;
    while (pos < query.size()) {
        const std::size_t amp = query.find('&', pos);
        const std::string pair = query.substr(pos, amp == std::string::npos ? amp : amp - pos);
        const std::size_t eq = pair.find('=');
        if (eq == std::string::npos) {
            throw std::invalid_argument("malformed server descriptor query");
        }
        const std::string key = pair.substr(0, eq);
        const std::string value = pair.substr(eq + 1);
        if (key == "v") {
            version = value;
            haveVersion = true;
        } else if (key == "fp") {
            descriptor.fingerprint = value;
            haveFingerprint = true;
        } else if (key == "facade") {
            if (!value.empty()) {
                descriptor.facades.push_back(value);
            }
        }
        // Unknown keys are ignored for forward compatibility.
        if (amp == std::string::npos) {
            break;
        }
        pos = amp + 1;
    }

    if (!haveVersion || version != "1") {
        throw std::invalid_argument("unsupported server descriptor version");
    }
    if (!haveFingerprint || !isFingerprint(descriptor.fingerprint)) {
        throw std::invalid_argument("server descriptor fp is not a 52-char base32 fingerprint");
    }
    return descriptor;
}

}  // namespace bazarish
