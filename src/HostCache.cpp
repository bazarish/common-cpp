// Bazarish project (c) 2026
#include "bazarish/HostCache.hpp"

#include <utility>

namespace bazarish::dns {

HostCache::HostCache(Lookup lookup, Now now)
    : lookup_(std::move(lookup))
    , now_(std::move(now))
{
}

Resolved HostCache::resolve(const std::string& host, const int port)
{
    const std::string key = host + ":" + std::to_string(port);
    std::shared_ptr<Pending> pending;
    std::uint64_t generation = 0;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const auto kept = kept_.find(key);
        if (kept != kept_.end()) {
            if (now_() < kept->second.until) {
                return kept->second.resolved;
            }
            kept_.erase(kept);
        }
        const auto flying = inFlight_.find(key);
        if (flying != inFlight_.end()) {
            const std::shared_ptr<Pending> shared = flying->second;
            settled_.wait(lock, [&shared]() { return shared->done; });
            return shared->result;
        }
        pending = std::make_shared<Pending>();
        inFlight_.emplace(key, pending);
        generation = generation_;
    }
    try {
        const Resolved result = lookup_(host, port);
        settle(key, pending, result, generation);
        return result;
    } catch (...) {
        Resolved failed;
        failed.error = "the lookup failed";
        settle(key, pending, failed, generation);
        throw;
    }
}

void HostCache::settle(const std::string& key, const std::shared_ptr<Pending>& pending,
    const Resolved& result, const std::uint64_t generation)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        pending->result = result;
        pending->done = true;
        const auto flying = inFlight_.find(key);
        if (flying != inFlight_.end() && flying->second == pending) {
            inFlight_.erase(flying);
        }
        if (result.error.empty() && result.ttl.count() > 0 && generation == generation_) {
            kept_[key] = Kept{result, now_() + result.ttl};
        }
    }
    settled_.notify_all();
}

void HostCache::invalidate()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    kept_.clear();
    inFlight_.clear();
    ++generation_;
}

std::size_t HostCache::size() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return kept_.size();
}

HostCache& hostCache()
{
    static HostCache shared(platformLookup);
    return shared;
}

}  // namespace bazarish::dns
