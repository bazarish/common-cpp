// Bazarish project (c) 2026
#include "bazarish/PairLink.hpp"
#include "bazarish/Percent.hpp"

#include "bazarish/Links.hpp"
#include "bazarish/I2p.hpp"
#include "bazarish/I2pAddress.hpp"
#include "bazarish/KeyedSeal.hpp"

#include <stdexcept>

namespace bazarish {

std::string encodePairLink(const PairLink& link)
{
    std::string query = "v=1&dest=" + link.dest;
    for (const std::string& reseed : link.reseeds) {
        query += "&reseed=" + reseed;
    }
    query += "&key=" + linkKeyText(link.key);
    return webLink(std::string(kPairKind) + query);
}

PairLink parsePairLink(const std::string& uri)
{
    const std::string query = linkQuery(uri, kPairKind);
    if (query.empty()) {
        throw std::invalid_argument("not a pair link");
    }

    PairLink link;
    std::string version;
    bool haveVersion = false;
    bool haveDest = false;
    bool haveKey = false;

    const std::optional<std::vector<QueryField>> fields = queryFields(query);
    if (!fields.has_value()) {
        throw std::invalid_argument("malformed pair link query");
    }
    for (const auto& [key, value] : *fields) {
        if (key == "v") {
            version = value;
            haveVersion = true;
        } else if (key == "dest") {
            link.dest = value;
            haveDest = true;
        } else if (key == "key") {
            link.key = linkKeyFromText(value);
            haveKey = true;
        } else if (key == "reseed") {
            if (!value.empty()) {
                if (!i2p::isReseedUrl(value)) {
                    throw std::invalid_argument(
                        "a reseed in a pair link must be an https URL (" + value + ")");
                }
                link.reseeds.push_back(value);
            }
        }
    }

    if (!haveVersion || version != "1") {
        throw std::invalid_argument("unsupported pair link version");
    }
    if (!haveDest) {
        throw std::invalid_argument("a pair link needs the address it points at");
    }
    if (!haveKey) {
        throw std::invalid_argument("a pair link needs the key its exchange is sealed under");
    }
    validateB32I2pHost(link.dest);
    return link;
}

}  // namespace bazarish
