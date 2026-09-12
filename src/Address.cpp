// Bazarish project (c) 2026
#include "bazarish/Address.hpp"

#include "bazarish/Crypto.hpp"

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
        // A bare fingerprint with no @server has nowhere to be delivered;
        // only aliases may omit the server part (main server implied).
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
