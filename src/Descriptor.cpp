// Bazarish project (c) 2026
#include "bazarish/Descriptor.hpp"

#include "bazarish/Crypto.hpp"
#include "bazarish/I2pAddress.hpp"

#include <map>
#include <stdexcept>
#include <string>

namespace {

constexpr char kPrefix[] = "bazarish://invite?";
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

std::string encodeDescriptor(const Descriptor& descriptor)
{
    return std::string(kPrefix) + "v=1&fp=" + descriptor.fingerprint + "&srv=" + descriptor.srv
        + "&srv_key=" + toBase64Url(descriptor.srvKeyDer);
}

Descriptor parseDescriptor(const std::string& uri)
{
    if (uri.size() <= kPrefixLen || uri.compare(0, kPrefixLen, kPrefix) != 0) {
        throw std::invalid_argument("not a bazarish://invite descriptor");
    }

    // The values are URL-safe by construction (base32 fingerprint, .b32.i2p host,
    // base64url key), so a plain split on '&' and '=' needs no percent-decoding.
    std::map<std::string, std::string> params;
    const std::string query = uri.substr(kPrefixLen);
    std::size_t pos = 0;
    while (pos < query.size()) {
        const std::size_t amp = query.find('&', pos);
        const std::string pair = query.substr(pos, amp == std::string::npos ? amp : amp - pos);
        const std::size_t eq = pair.find('=');
        if (eq == std::string::npos) {
            throw std::invalid_argument("malformed descriptor query");
        }
        params[pair.substr(0, eq)] = pair.substr(eq + 1);
        if (amp == std::string::npos) {
            break;
        }
        pos = amp + 1;
    }

    const auto need = [&params](const char* key) -> const std::string& {
        const auto found = params.find(key);
        if (found == params.end()) {
            throw std::invalid_argument(std::string("descriptor missing ") + key);
        }
        return found->second;
    };

    if (need("v") != "1") {
        throw std::invalid_argument("unsupported descriptor version");
    }

    Descriptor descriptor;
    descriptor.fingerprint = need("fp");
    if (!isFingerprint(descriptor.fingerprint)) {
        throw std::invalid_argument("descriptor fp is not a 52-char base32 fingerprint");
    }
    descriptor.srv = need("srv");
    validateB32I2pHost(descriptor.srv);
    descriptor.srvKeyDer = fromBase64Url(need("srv_key"));
    if (descriptor.srvKeyDer.empty()) {
        throw std::invalid_argument("descriptor srv_key is empty");
    }
    return descriptor;
}

}  // namespace bazarish
