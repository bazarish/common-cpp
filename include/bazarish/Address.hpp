// Bazarish project (c) 2026
#pragma once

#include <optional>
#include <string>

namespace bazarish {

inline constexpr std::size_t kAliasMaxLength = 16;
inline constexpr std::size_t kAliasMinLength = 1;

struct Address {
    enum class Kind {
        eFingerprint,
        eAlias,
    };

    Kind kind = Kind::eAlias;
    std::string local;
    std::string server;

    bool operator==(const Address&) const = default;
};

std::optional<Address> parseAddress(const std::string& text);
std::string formatAddress(const Address& address);

// True for a well-formed key fingerprint (52 chars of base32).
bool isFingerprint(const std::string& text);
void requireFingerprint(const std::string& text);
bool isAlias(const std::string& text);

inline constexpr char kAliasSigil = '!';

std::string normalizeAlias(const std::string& typed);

}  // namespace bazarish
