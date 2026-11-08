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

char asciiLowerChar(const char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool allAliasChars(const std::string_view text)
{
    for (const char c : text) {
        if (!isAliasChar(asciiLowerChar(c))) {
            return false;
        }
    }
    return true;
}

std::string lowered(const std::string_view text)
{
    std::string out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(asciiLowerChar(c));
    }
    return out;
}

std::string_view withoutSigil(const std::string_view typed)
{
    return (!typed.empty() && typed.front() == bazarish::kAliasSigil) ? typed.substr(1) : typed;
}

std::optional<bazarish::AliasProblem> nameProblem(const std::string_view name)
{
    if (name.size() < bazarish::kAliasMinLength || name.size() > bazarish::kAliasMaxLength) {
        return bazarish::AliasProblem::eNameLength;
    }
    if (!allAliasChars(name)) {
        return bazarish::AliasProblem::eNameChars;
    }
    return std::nullopt;
}

std::string problemText(const bazarish::AliasProblem problem)
{
    switch (problem) {
    case bazarish::AliasProblem::eNameLength:
        return "alias must be " + std::to_string(bazarish::kAliasMinLength) + "-"
            + std::to_string(bazarish::kAliasMaxLength) + " characters";
    case bazarish::AliasProblem::eNameChars: return "alias may contain only a-z and 0-9";
    case bazarish::AliasProblem::eWordLength:
        return "an alias word is at most " + std::to_string(bazarish::kAliasWordMaxLength)
            + " characters";
    case bazarish::AliasProblem::eWordChars: return "an alias word may contain only a-z and 0-9";
    case bazarish::AliasProblem::eWordEmpty: return "nothing follows the dash of an alias word";
    }
    throw std::logic_error("unknown alias problem");
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

std::optional<AliasProblem> aliasWordProblem(const std::string_view word)
{
    if (word.size() > kAliasWordMaxLength) {
        return AliasProblem::eWordLength;
    }
    if (!allAliasChars(word)) {
        return AliasProblem::eWordChars;
    }
    return std::nullopt;
}

std::optional<AliasProblem> aliasQueryProblem(const std::string_view typed)
{
    const std::string_view query = withoutSigil(typed);
    const std::size_t separator = query.find(kAliasWordSeparator);
    if (const std::optional<AliasProblem> name = nameProblem(query.substr(0, separator)); name) {
        return name;
    }
    if (separator == std::string_view::npos) {
        return std::nullopt;
    }
    const std::string_view word = query.substr(separator + 1);
    if (word.empty()) {
        return AliasProblem::eWordEmpty;
    }
    return aliasWordProblem(word);
}

std::string normalizeAlias(const std::string& typed)
{
    const std::string_view name = withoutSigil(typed);
    if (const std::optional<AliasProblem> problem = nameProblem(name); problem) {
        throw std::runtime_error(problemText(*problem));
    }
    return lowered(name);
}

std::string normalizeAliasWord(const std::string& typed)
{
    if (const std::optional<AliasProblem> problem = aliasWordProblem(typed); problem) {
        throw std::runtime_error(problemText(*problem));
    }
    return lowered(typed);
}

AliasQuery parseAliasQuery(const std::string& typed)
{
    if (const std::optional<AliasProblem> problem = aliasQueryProblem(typed); problem) {
        throw std::runtime_error(problemText(*problem));
    }
    const std::string_view query = withoutSigil(typed);
    const std::size_t separator = query.find(kAliasWordSeparator);
    if (separator == std::string_view::npos) {
        return {lowered(query), {}};
    }
    return {lowered(query.substr(0, separator)), lowered(query.substr(separator + 1))};
}

std::string aliasQueryText(const AliasQuery& query)
{
    return query.word.empty() ? query.name : query.name + kAliasWordSeparator + query.word;
}

}  // namespace bazarish
