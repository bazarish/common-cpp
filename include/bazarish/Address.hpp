// Bazarish project (c) 2026
#pragma once

#include <optional>
#include <string>

namespace bazarish {

// Aliases are short enough to never collide with the 52-character
// fingerprint form.
inline constexpr std::size_t kAliasMaxLength = 32;
inline constexpr std::size_t kAliasMinLength = 1;

// Address forms:
//   <fingerprint>@<server-fingerprint>  - fully qualified
//   <alias>@<server-fingerprint>        - alias at a specific server
//   <alias>                             - main-server alias (server empty)
struct Address {
    enum class Kind {
        eFingerprint,
        eAlias,
    };

    Kind kind = Kind::eAlias;
    // Fingerprint or alias, depending on kind.
    std::string local;
    // Server fingerprint; empty means the main server is implied.
    std::string server;

    bool operator==(const Address&) const = default;
};

// Returns nullopt for anything that is not a well-formed address.
std::optional<Address> parseAddress(const std::string& text);
std::string formatAddress(const Address& address);

// True for a well-formed key fingerprint (52 chars of base32).
bool isFingerprint(const std::string& text);
// True for a well-formed alias: [a-z0-9_.-], length limits, must not
// start or end with a separator.
bool isAlias(const std::string& text);

}  // namespace bazarish
