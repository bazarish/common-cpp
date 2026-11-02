// Bazarish project (c) 2026
#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

namespace bazarish {

inline constexpr char kUriScheme[] = "bazarish";
// Everything after '#' stays in the browser: the site never receives a link's content.
inline constexpr char kWebLinkPrefix[] = "https://bazari.sh/#";
inline constexpr char kSchemeLinkPrefix[] = "bazarish://";

inline constexpr char kInviteKind[] = "invite?";
inline constexpr char kServerKind[] = "server?";
inline constexpr char kPairKind[] = "pair?";
inline constexpr char kSignKind[] = "sign?";

inline std::string linkTail(const std::string_view link)
{
    for (const std::string_view prefix : {std::string_view(kWebLinkPrefix),
             std::string_view(kSchemeLinkPrefix)}) {
        if (link.size() > prefix.size() && link.substr(0, prefix.size()) == prefix) {
            return std::string(link.substr(prefix.size()));
        }
    }
    return {};
}

inline std::string webLink(const std::string_view tail)
{
    return std::string(kWebLinkPrefix) + std::string(tail);
}

inline std::string schemeLink(const std::string_view tail)
{
    return std::string(kSchemeLinkPrefix) + std::string(tail);
}

inline std::string canonicalLink(const std::string_view link)
{
    const std::string tail = linkTail(link);
    if (tail.empty()) {
        throw std::invalid_argument("not a Bazarish link");
    }
    return schemeLink(tail);
}

inline std::string linkQuery(const std::string_view link, const std::string_view kind)
{
    const std::string tail = linkTail(link);
    if (tail.size() <= kind.size() || std::string_view(tail).substr(0, kind.size()) != kind) {
        return {};
    }
    return tail.substr(kind.size());
}

}  // namespace bazarish
