// Bazarish project (c) 2026
#include "WarmDestPool.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Log.hpp>

#include <algorithm>
#include <vector>

namespace bazarish::client {

WarmDestPool::WarmDestPool(bazarish::i2p::Router& router, std::size_t size, int tunnelQuantity)
    : router_(router)
    , size_(size)
    , tunnelQuantity_(tunnelQuantity)
{
}

WarmDestPool::~WarmDestPool()
{
    stop();
    if (warmer_.joinable()) {
        warmer_.join();
    }
}

void WarmDestPool::start()
{
    if (running_.exchange(true)) {
        return;
    }
    warmer_ = std::thread([this]() { warmerLoop(); });
}

void WarmDestPool::stop()
{
    running_ = false;
    cv_.notify_all();
}

std::shared_ptr<bazarish::i2p::Endpoint> WarmDestPool::acquire()
{
    std::shared_ptr<bazarish::i2p::Endpoint> dest;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        // A dest the transport lost while it waited here cannot dial, and handing
        // it out costs the caller a failed lookup for nothing.
        while (!ready_.empty()) {
            dest = std::move(ready_.front());
            ready_.pop_front();
            if (!dest->lost()) {
                break;
            }
            dest.reset();
        }
        refillWanted_ = true;
    }
    cv_.notify_all();  // wake the warmer to refill
    return dest;
}

void WarmDestPool::flush()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        ready_.clear();
        ++generation_;
        refillWanted_ = true;
    }
    cv_.notify_all();
}

void WarmDestPool::warmerLoop()
{
    // Destinations still warming, owned by this loop until ready or abandoned.
    std::vector<Building> building;

    while (running_.load()) {
        std::size_t toCreate = 0;
        std::size_t generation = 0;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            generation = generation_;
            std::erase_if(building, [generation](const Building& item) {
                return item.generation != generation;
            });
            const std::size_t have = ready_.size() + building.size();
            toCreate = size_ > have ? size_ - have : 0;
        }

        // Create the shortfall (createEndpoint returns at once; the tunnels build in
        // the background, which is what waiting on ready() below tracks). A single-use
        // outbound dest stays UNPUBLISHED - the reply rides the stream's inline
        // leaseset - so it never touches the netDb.
        for (std::size_t i = 0; i < toCreate && running_.load(); ++i) {
            try {
                auto endpoint = router_.createEndpoint(bazarish::i2p::EndpointConfig{
                    router_.generateKeys(), tunnelPrivacy(), tunnelQuantity_,
                    /*published=*/false, "Warm reserve"});
                if (endpoint) {
                    building.push_back(
                        {std::move(endpoint), std::chrono::steady_clock::now(), generation});
                }
            } catch (const std::exception& error) {
                bazarish::log::warn("warm-pool: createEndpoint failed: {}", error.what());
            }
        }

        // Promote any dest whose tunnels are up; abandon one that never warmed.
        const auto now = std::chrono::steady_clock::now();
        for (auto it = building.begin(); it != building.end();) {
            if (it->endpoint && it->endpoint->ready()) {
                std::size_t warm = 0;
                {
                    const std::lock_guard<std::mutex> lock(mutex_);
                    ready_.push_back(std::move(it->endpoint));
                    warm = ready_.size();
                }
                bazarish::log::info("warm-pool: dest ready ({} warm, target {})", warm, size_);
                it = building.erase(it);
            } else if (now - it->startedAt > buildTimeout_) {
                // Best-effort: a dest that could not build tunnels in time (e.g. a
                // firewalled router with no peers) is dropped; the loop retries.
                bazarish::log::warn("warm-pool: abandoning a dest that never warmed");
                it = building.erase(it);
            } else {
                ++it;
            }
        }

        // Sleep until the next tick (woken early by an acquire). A short tick keeps
        // ready() polling responsive while still building in the background.
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(building.empty() ? 1000 : 300),
            [this]() { return !running_.load() || refillWanted_; });
        refillWanted_ = false;
    }
}

}  // namespace bazarish::client
