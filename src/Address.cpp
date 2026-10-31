// Bazarish project (c) 2026
#include "bazarish/Address.hpp"

#include "bazarish/Crypto.hpp"

#include <stdexcept>
#include <string_view>

namespace {

bool isBase32Char(const char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
}

bool isAliasChar(const char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

}  // namespace

namespace bazarish {

bool isFingerprint(const std::string& text)
{
    if (text.size() != kFingerprintTextLength) {
        return false;
    }
    for (const char c : text) {
        if (!isBase32Char(c)) {
            return false;
        }
    }
    return true;
}

void requireFingerprint(const std::string& text)
{
    if (!isFingerprint(text)) {
        throw std::invalid_argument("not a fingerprint: " + text);
    }
}

bool isAlias(const std::string& text)
{
    if (text.size() < kAliasMinLength || text.size() > kAliasMaxLength) {
        return false;
    }
    for (const char c : text) {
        if (!isAliasChar(c)) {
            return false;
        }
    }
    return true;
}

std::string normalizeAlias(const std::string& typed)
{
    const std::string_view name = (!typed.empty() && typed.front() == kAliasSigil)
        ? std::string_view(typed).substr(1)
        : std::string_view(typed);
    if (name.size() < kAliasMinLength || name.size() > kAliasMaxLength) {
        throw std::runtime_error("alias must be " + std::to_string(kAliasMinLength) + "-"
            + std::to_string(kAliasMaxLength) + " characters");
    }
    std::string normalized;
    normalized.reserve(name.size());
    for (const char c : name) {
        normalized.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
    }
    if (!isAlias(normalized)) {
        throw std::runtime_error("alias may contain only a-z and 0-9");
    }
    return normalized;
}

std::string normalizeAliasWord(const std::string& typed)
{
    if (typed.size() > kAliasWordMaxLength) {
        throw std::runtime_error(
            "an alias word is at most " + std::to_string(kAliasWordMaxLength) + " characters");
    }
    std::string normalized;
    normalized.reserve(typed.size());
    for (const char c : typed) {
        const char lower = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        if (!isAliasChar(lower)) {
            throw std::runtime_error("an alias word may contain only a-z and 0-9");
        }
        normalized.push_back(lower);
    }
    return normalized;
}

AliasQuery parseAliasQuery(const std::string& typed)
{
    const std::size_t sigil = (!typed.empty() && typed.front() == kAliasSigil) ? 1 : 0;
    const std::size_t separator = typed.find(kAliasWordSeparator, sigil);
    if (separator == std::string::npos) {
        return {normalizeAlias(typed.substr(sigil)), {}};
    }
    const std::string word = normalizeAliasWord(typed.substr(separator + 1));
    if (word.empty()) {
        throw std::runtime_error("nothing follows the dash of an alias word");
    }
    return {normalizeAlias(typed.substr(sigil, separator - sigil)), word};
}

std::string aliasQueryText(const AliasQuery& query)
{
    return query.word.empty() ? query.name : query.name + kAliasWordSeparator + query.word;
}

}  // namespace bazarish
