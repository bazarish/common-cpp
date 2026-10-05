// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <string>

namespace bazarish::service {

// A stateless portal session token issued after a successful sign-in-with-key
// login. The token is `userId.exp.tag` where tag = HMAC(secret, userId|exp) -
// all cookie-safe characters (base32 fingerprint, digits, hex), so it drops
// straight into a Set-Cookie value with no encoding. Stateless: the portal
// verifies it without storage; logout/rotation is by shortening the TTL or
// rolling the secret.
class PortalSession {
public:
    explicit PortalSession(std::string secret, std::int64_t ttlSeconds = 3600);

    // A token binding userId for ttlSeconds from now.
    std::string issue(const std::string& userId, std::int64_t now) const;

    // Returns the userId from a valid, unexpired token; throws otherwise.
    std::string verify(const std::string& token, std::int64_t now) const;

private:
    std::string secret_;
    std::int64_t ttlSeconds_;
};

}  // namespace bazarish::service
