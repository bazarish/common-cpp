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

std::optional<Address> parseAddress(const std::string& text)
{
    const std::size_t at = text.find('@');
    if (at != text.rfind('@')) {
        return std::nullopt;
    }

    const std::string local = at == std::string::npos ? text : text.substr(0, at);
    const std::string server = at == std::string::npos ? std::string() : text.substr(at + 1);

    if (at != std::string::npos && !isFingerprint(server)) {
        return std::nullopt;
    }

    Address address;
    address.server = server;
    address.local = local;
    if (isFingerprint(local)) {
        if (server.empty()) {
            return std::nullopt;
        }
        address.kind = Address::Kind::eFingerprint;
        return address;
    }
    if (isAlias(local)) {
        address.kind = Address::Kind::eAlias;
        return address;
    }
    return std::nullopt;
}

std::string formatAddress(const Address& address)
{
    if (address.server.empty()) {
        return address.local;
    }
    return address.local + "@" + address.server;
}

}  // namespace bazarish
