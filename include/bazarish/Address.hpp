// Bazarish project (c) 2026
#pragma once

#include <optional>
#include <string>

namespace bazarish {

// Aliases are short enough to never collide with the 52-character
// fingerprint form. The upper bound is also the longest name the central
// registry sells, and its cheapest tier.
inline constexpr std::size_t kAliasMaxLength = 16;
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
// Throws unless `text` is one. Every store names its records after a fingerprint,
// so a name that is not one could leave the directory it is joined to.
void requireFingerprint(const std::string& text);
// True for a well-formed alias: [a-z0-9] within the length limits. Separators
// are deliberately absent - they would let two names differ only by a character
// nobody reads, and the price of a name follows its length alone.
bool isAlias(const std::string& text);

}  // namespace bazarish
