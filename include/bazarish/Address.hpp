// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <string>

namespace bazarish {

inline constexpr std::size_t kAliasMaxLength = 16;
inline constexpr std::size_t kAliasMinLength = 1;
inline constexpr std::size_t kAliasWordMaxLength = 16;
inline constexpr char kAliasWordSeparator = '-';

bool isFingerprint(const std::string& text);
void requireFingerprint(const std::string& text);
bool isAlias(const std::string& text);

inline constexpr char kAliasSigil = '!';

std::string normalizeAlias(const std::string& typed);

// "name" or "name-word", the sigil optional; the word is the owner's and may be absent.
struct AliasQuery {
    std::string name;
    std::string word{};

    bool operator==(const AliasQuery&) const = default;
};

AliasQuery parseAliasQuery(const std::string& typed);
// An empty word is allowed and means none.
std::string normalizeAliasWord(const std::string& typed);
std::string aliasQueryText(const AliasQuery& query);

}  // namespace bazarish
