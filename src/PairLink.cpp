// Bazarish project (c) 2026
#include "bazarish/PairLink.hpp"

#include "bazarish/I2pAddress.hpp"

#include <stdexcept>

namespace {

constexpr char kPrefix[] = "bazarish://pair?";
constexpr std::size_t kPrefixLen = sizeof(kPrefix) - 1;
constexpr char kHttps[] = "https://";

}  // namespace

namespace bazarish {

std::string encodePairLink(const PairLink& link)
{
    std::string uri = std::string(kPrefix) + "v=1&dest=" + link.dest;
    for (const std::string& reseed : link.reseeds) {
        uri += "&reseed=" + reseed;
    }
    return uri;
}

PairLink parsePairLink(const std::string& uri)
{
    if (uri.size() <= kPrefixLen || uri.compare(0, kPrefixLen, kPrefix) != 0) {
        throw std::invalid_argument("not a bazarish://pair link");
    }

    PairLink link;
    std::string version;
    bool haveVersion = false;
    bool haveDest = false;

    const std::string query = uri.substr(kPrefixLen);
    std::size_t pos = 0;
    while (pos < query.size()) {
        const std::size_t amp = query.find('&', pos);
        const std::string pair = query.substr(pos, amp == std::string::npos ? amp : amp - pos);
        const std::size_t eq = pair.find('=');
        if (eq == std::string::npos) {
            throw std::invalid_argument("malformed pair link query");
        }
        const std::string key = pair.substr(0, eq);
        const std::string value = pair.substr(eq + 1);
        if (key == "v") {
            version = value;
            haveVersion = true;
        } else if (key == "dest") {
            link.dest = value;
            haveDest = true;
        } else if (key == "reseed") {
            if (!value.empty()) {
                if (value.rfind(kHttps, 0) != 0) {
                    throw std::invalid_argument(
                        "a reseed in a pair link must be an https URL (" + value + ")");
                }
                link.reseeds.push_back(value);
            }
        }
        if (amp == std::string::npos) {
            break;
        }
        pos = amp + 1;
    }

    if (!haveVersion || version != "1") {
        throw std::invalid_argument("unsupported pair link version");
    }
    if (!haveDest) {
        throw std::invalid_argument("a pair link needs the address it points at");
    }
    validateB32I2pHost(link.dest);
    return link;
}

}  // namespace bazarish
