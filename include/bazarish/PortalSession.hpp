// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>

namespace bazarish::service {

class PortalSession {
public:
    explicit PortalSession(std::string secret, std::int64_t ttlSeconds = 3600);

    std::string issue(const std::string& userId, std::int64_t now) const;

    std::string verify(const std::string& token, std::int64_t now) const;

    // Signing out ends the token itself, not just the browser's copy of it.
    void revoke(const std::string& token, std::int64_t now);

private:
    std::string secret_;
    std::int64_t ttlSeconds_;
    mutable std::mutex revokedMutex_;
    std::map<std::string, std::int64_t> revoked_;
};

}  // namespace bazarish::service
