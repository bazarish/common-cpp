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
    cv_.notify_all();
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

void WarmDestPool::setWanted(const bool wanted)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (wanted_ == wanted) {
            return;
        }
        wanted_ = wanted;
        ++generation_;
        refillWanted_ = true;
    }
    cv_.notify_all();
}

void WarmDestPool::warmerLoop()
{
    std::vector<Building> building;

    while (running_.load()) {
        std::size_t toCreate = 0;
        std::size_t generation = 0;
        std::deque<std::shared_ptr<bazarish::i2p::Endpoint>> unwanted;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            generation = generation_;
            std::erase_if(building, [generation](const Building& item) {
                return item.generation != generation;
            });
            if (!wanted_) {
                unwanted.swap(ready_);
            }
            const std::size_t have = ready_.size() + building.size();
            toCreate = wanted_ && size_ > have ? size_ - have : 0;
        }
        unwanted.clear();

        for (std::size_t i = 0; i < toCreate && running_.load(); ++i) {
            try {
                bazarish::i2p::EndpointConfig config;
                config.privacy = tunnelPrivacy();
                config.tunnelQuantity = tunnelQuantity_;
                config.published = false;
                config.label = "Warm reserve";
                auto endpoint = router_.createEndpoint(config);
                if (endpoint) {
                    building.push_back(
                        {std::move(endpoint), std::chrono::steady_clock::now(), generation});
                }
            } catch (const std::exception& error) {
                bazarish::log::warn("warm-pool: createEndpoint failed: {}", error.what());
            }
        }

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
                bazarish::log::warn("warm-pool: abandoning a dest that never warmed");
                it = building.erase(it);
            } else {
                ++it;
            }
        }

        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(building.empty() ? 1000 : 300),
            [this]() { return !running_.load() || refillWanted_; });
        refillWanted_ = false;
    }
}

}  // namespace bazarish::client
