// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <string>

namespace bazarish::service {

// A stateless portal session token issued after a successful sign-in-with-key login.
class PortalSession {
public:
    explicit PortalSession(std::string secret, std::int64_t ttlSeconds = 3600);

    std::string issue(const std::string& userId, std::int64_t now) const;

    std::string verify(const std::string& token, std::int64_t now) const;

private:
    std::string secret_;
    std::int64_t ttlSeconds_;
};

}  // namespace bazarish::service
