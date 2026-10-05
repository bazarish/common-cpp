// Bazarish project (c) 2026
#pragma once

#include <bazarish/Portal.hpp>

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish::service {

// Issues and verifies sign-in-with-key login challenges for one service portal.
class LoginChallenge {
public:
    LoginChallenge(std::string secret, LoginConsumer consumer, std::int64_t windowSeconds = 300);

    std::string issue(std::int64_t now);

    std::string verify(
        const std::string& challenge, const std::string& loginBlob, std::int64_t now);

    LoginConsumer consumer() const;
    void setConsumer(LoginConsumer consumer);

private:
    void pruneExpired(std::int64_t now);
    std::string currentCanonical() const;

    std::string secret_;
    LoginConsumer consumer_;
    std::string canonicalConsumer_;
    std::int64_t windowSeconds_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> consumed_;
};

}  // namespace bazarish::service
