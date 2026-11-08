// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

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

// Why typed text is not an alias query, so a caller can say it in its own words.
enum class AliasProblem { eNameLength, eNameChars, eWordLength, eWordChars, eWordEmpty };
std::optional<AliasProblem> aliasQueryProblem(std::string_view typed);
std::optional<AliasProblem> aliasWordProblem(std::string_view word);
std::string aliasQueryText(const AliasQuery& query);

}  // namespace bazarish
