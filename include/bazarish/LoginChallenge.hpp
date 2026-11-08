// Bazarish project (c) 2026
#pragma once

#include <bazarish/Portal.hpp>

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish::service {

class LoginChallenge {
public:
    // Called on every challenge and check, so a changed setting applies at once.
    using ConsumerFn = std::function<LoginConsumer()>;

    LoginChallenge(std::string secret, ConsumerFn consumer,
        std::int64_t windowSeconds = kLoginWindowSeconds);
    LoginChallenge(std::string secret, LoginConsumer consumer,
        std::int64_t windowSeconds = kLoginWindowSeconds);

    std::string issue(std::int64_t now, const std::string& callback = {});

    std::string verify(
        const std::string& challenge, const std::string& loginBlob, std::int64_t now);

    LoginConsumer consumer() const;

private:
    void pruneExpired(std::int64_t now);
    std::string currentCanonical() const;

    std::string secret_;
    const ConsumerFn consumer_;
    std::int64_t windowSeconds_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> consumed_;
};

}  // namespace bazarish::service
