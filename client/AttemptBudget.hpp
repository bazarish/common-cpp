// Bazarish project (c) 2026
#pragma once

#include <chrono>

namespace bazarish::client {

// One run of tries against a deadline: another try starts only when the time left pays for its
// wait and for the dial it makes.
class AttemptBudget {
public:
    explicit AttemptBudget(const std::chrono::steady_clock::duration run)
        : deadline_(std::chrono::steady_clock::now() + run)
    {
    }

    bool pays(const std::chrono::steady_clock::duration gap,
        const std::chrono::steady_clock::duration attempt) const
    {
        return std::chrono::steady_clock::now() + gap + attempt <= deadline_;
    }

    std::chrono::steady_clock::time_point deadline() const { return deadline_; }

    std::chrono::seconds left() const
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            deadline_ - std::chrono::steady_clock::now());
    }

private:
    const std::chrono::steady_clock::time_point deadline_;
};

}  // namespace bazarish::client
