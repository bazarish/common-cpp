// Bazarish project (c) 2026
#include "bazarish/PortalSession.hpp"

#include "bazarish/Hmac.hpp"
#include "bazarish/Log.hpp"

#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace {

std::string tagFor(const std::string& secret, const std::string& userId, const std::string& exp)
{
    return hmacSha256Hex(secret, userId + "|" + exp);
}

struct TokenParts {
    std::string userId;
    std::string exp;
    std::string tag;
};

TokenParts partsOf(const std::string& token)
{
    const auto firstDot = token.find('.');
    const auto secondDot = firstDot == std::string::npos ? std::string::npos
                                                         : token.find('.', firstDot + 1);
    if (firstDot == std::string::npos || secondDot == std::string::npos) {
        throw std::runtime_error("session token malformed");
    }
    return {token.substr(0, firstDot), token.substr(firstDot + 1, secondDot - firstDot - 1),
        token.substr(secondDot + 1)};
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
    const auto [userId, exp, tag] = partsOf(token);

    if (!constantTimeEqual(tag, tagFor(secret_, userId, exp))) {
        throw std::runtime_error("session token signature invalid");
    }
    if (std::stoll(exp) <= now) {
        throw std::runtime_error("session token expired");
    }
    {
        const std::lock_guard<std::mutex> lock(revokedMutex_);
        if (revoked_.count(tag) != 0) {
            throw std::runtime_error("session token revoked");
        }
    }
    return userId;
}

void PortalSession::revoke(const std::string& token, const std::int64_t now)
{
    try {
        (void)verify(token, now);
    } catch (const std::exception& error) {
        bazarish::log::debug("portal session: nothing to revoke: {}", error.what());
        return;
    }
    const TokenParts parts = partsOf(token);
    const std::lock_guard<std::mutex> lock(revokedMutex_);
    std::erase_if(revoked_, [now](const auto& entry) { return entry.second <= now; });
    revoked_[parts.tag] = std::stoll(parts.exp);
}

}  // namespace bazarish::service
