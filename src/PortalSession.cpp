// Bazarish project (c) 2026
#include "bazarish/PortalSession.hpp"

#include "bazarish/Hmac.hpp"

#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace {

std::string tagFor(const std::string& secret, const std::string& userId, const std::string& exp)
{
    return hmacSha256Hex(secret, userId + "|" + exp);
}

}  // namespace

PortalSession::PortalSession(std::string secret, const std::int64_t ttlSeconds)
    : secret_(std::move(secret))
    , ttlSeconds_(ttlSeconds)
{
}

std::string PortalSession::issue(const std::string& userId, const std::int64_t now) const
{
    const std::string exp = std::to_string(now + ttlSeconds_);
    return userId + "." + exp + "." + tagFor(secret_, userId, exp);
}

std::string PortalSession::verify(const std::string& token, const std::int64_t now) const
{
    const auto firstDot = token.find('.');
    const auto secondDot = firstDot == std::string::npos ? std::string::npos
                                                         : token.find('.', firstDot + 1);
    if (firstDot == std::string::npos || secondDot == std::string::npos) {
        throw std::runtime_error("session token malformed");
    }
    const std::string userId = token.substr(0, firstDot);
    const std::string exp = token.substr(firstDot + 1, secondDot - firstDot - 1);
    const std::string tag = token.substr(secondDot + 1);

    if (!constantTimeEqual(tag, tagFor(secret_, userId, exp))) {
        throw std::runtime_error("session token signature invalid");
    }
    if (std::stoll(exp) <= now) {
        throw std::runtime_error("session token expired");
    }
    return userId;
}

}  // namespace bazarish::service
