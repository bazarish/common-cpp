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

// Percent-encodes a free-form value (the display name) so arbitrary text -
// spaces, '&', '=', UTF-8 - survives the '&'/'=' split with no ambiguity. Only
// the RFC-3986 unreserved set is left as-is.
std::string percentEncode(const std::string& value)
{
    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0F]);
        }
    }
    return out;
}

// Decodes a percent-encoded value. A malformed escape is left verbatim rather
// than throwing: the name is cosmetic, never a trust anchor.
std::string percentDecode(const std::string& value)
{
    const auto hexValue = [](const char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        return -1;
    };
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%' && i + 2 < value.size()) {
            const int hi = hexValue(value[i + 1]);
            const int lo = hexValue(value[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(value[i]);
    }
    return out;
}

}  // namespace

namespace bazarish {

std::string encodeDescriptor(const Descriptor& descriptor)
{
    std::string uri = std::string(kPrefix) + "v=1&fp=" + descriptor.fingerprint
        + "&srv=" + descriptor.srv + "&srv_key=" + toBase64Url(descriptor.srvKeyDer);
    // The name is optional and percent-encoded; older invites simply omit it.
    if (!descriptor.name.empty()) {
        uri += "&name=" + percentEncode(descriptor.name);
    }
    return uri;
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
    // The name is optional: a descriptor minted before names existed has none.
    const auto nameParam = params.find("name");
    if (nameParam != params.end()) {
        descriptor.name = percentDecode(nameParam->second);
    }
    return descriptor;
}

}  // namespace bazarish
