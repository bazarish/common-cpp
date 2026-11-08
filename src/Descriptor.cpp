// Bazarish project (c) 2026
#include "bazarish/Descriptor.hpp"

#include "bazarish/Links.hpp"
#include "bazarish/Percent.hpp"
#include "bazarish/Address.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/I2pAddress.hpp"

#include <map>
#include <stdexcept>
#include <string>

namespace bazarish {

std::string encodeDescriptor(const Descriptor& descriptor)
{
    std::string query = "v=1&fp=" + descriptor.fingerprint + "&dest=" + descriptor.dest;
    if (!descriptor.name.empty()) {
        query += "&name=" + percentEncode(descriptor.name);
    }
    return webLink(std::string(kInviteKind) + query);
}

Descriptor parseDescriptor(const std::string& uri)
{
    const std::string query = linkQuery(uri, kInviteKind);
    if (query.empty()) {
        throw std::invalid_argument("not an invite link");
    }

    std::map<std::string, std::string> params;
    const std::optional<std::vector<QueryField>> fields = queryFields(query);
    if (!fields.has_value()) {
        throw std::invalid_argument("malformed descriptor query");
    }
    for (const auto& [key, value] : *fields) {
        params[key] = value;
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
