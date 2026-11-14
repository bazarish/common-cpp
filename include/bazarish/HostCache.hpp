// Bazarish project (c) 2026
#pragma once

#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish::dns {

// Chrome's kCacheEntryTTLSeconds and kMinimumTTLSeconds, net/dns/host_resolver_manager_job.cc.
inline constexpr std::chrono::seconds kSystemAnswerTtl{60};
inline constexpr std::chrono::seconds kMinimumAnswerTtl{60};

struct Resolved {
    std::vector<boost::asio::ip::address> addresses;
    std::chrono::seconds ttl{0};
    std::string error;
};

using Lookup = std::function<Resolved(const std::string& host, int port)>;
using Now = std::function<std::chrono::steady_clock::time_point()>;

// Chrome's HostCache: an answer serves until its TTL ends or the network changes, a failure is
// not kept (kNegativeCacheEntryTTLSeconds is 0), and callers asking at once share one lookup.
class HostCache {
public:
    explicit HostCache(Lookup lookup, Now now = std::chrono::steady_clock::now);

    Resolved resolve(const std::string& host, int port);
    void invalidate();
    std::size_t size() const;

private:
    struct Pending {
        bool done = false;
        Resolved result;
    };
    struct Kept {
        Resolved resolved;
        std::chrono::steady_clock::time_point until;
    };

    void settle(const std::string& key, const std::shared_ptr<Pending>& pending,
        const Resolved& result, std::uint64_t generation);

    const Lookup lookup_;
    const Now now_;
    mutable std::mutex mutex_;
    std::condition_variable settled_;
    std::map<std::string, Kept> kept_;
    std::map<std::string, std::shared_ptr<Pending>> inFlight_;
    std::uint64_t generation_ = 0;
};

// The process's one cache over the platform's lookup.
HostCache& hostCache();

// Android asks A, AAAA where IPv6 reaches out, and HTTPS through the platform's DNS, as Chrome
// does; elsewhere the system resolver answers.
Resolved platformLookup(const std::string& host, int port);

}  // namespace bazarish::dns
