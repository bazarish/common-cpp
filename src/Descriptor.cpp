// Bazarish project (c) 2026
#include "bazarish/Descriptor.hpp"

#include "bazarish/Links.hpp"
#include "bazarish/Address.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/I2pAddress.hpp"

#include <map>
#include <stdexcept>
#include <string_view>
#include <string>

namespace {

constexpr std::string_view kPrefix = bazarish::kInviteUri;

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
        + "&dest=" + descriptor.dest;
    if (!descriptor.name.empty()) {
        uri += "&name=" + percentEncode(descriptor.name);
    }
    return uri;
}

Descriptor parseDescriptor(const std::string& uri)
{
    if (uri.size() <= kPrefix.size() || uri.compare(0, kPrefix.size(), kPrefix) != 0) {
        throw std::invalid_argument("not a bazarish://invite descriptor");
    }

    std::map<std::string, std::string> params;
    const std::string query = uri.substr(kPrefix.size());
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
    descriptor.dest = need("dest");
    validateB32I2pHost(descriptor.dest);
    const auto nameParam = params.find("name");
    if (nameParam != params.end()) {
        descriptor.name = percentDecode(nameParam->second);
    }
    return descriptor;
}

}  // namespace bazarish
