// Bazarish project (c) 2026
#pragma once

#include <bazarish/Limits.hpp>

#include <cstddef>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace bazarish::client {

// Mailbox items this device holds unopened until what they wait for arrives; read by the mail waiter.
class KeptMail {
public:
    // False when the bound is reached and the item cannot be kept.
    bool keep(const std::string& id)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!ids_.contains(id) && ids_.size() >= kMaxDeferredMailItems) {
            return false;
        }
        ids_.insert(id);
        return true;
    }

    void release(const std::string& id)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        ids_.erase(id);
    }

    bool holds(const std::string& id) const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return ids_.contains(id);
    }

    std::vector<std::string> ids() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return {ids_.begin(), ids_.end()};
    }

private:
    mutable std::mutex mutex_;
    std::set<std::string> ids_;
};

}  // namespace bazarish::client
