// Bazarish project (c) 2026
#include "WarmDestPool.hpp"

#include <bazarish/Log.hpp>

#include <algorithm>
#include <vector>

namespace bazarish::client {

namespace {

constexpr std::chrono::milliseconds kIdlePoll{1000};
constexpr std::chrono::milliseconds kBuildingPoll{300};

}  // namespace

WarmDestPool::WarmDestPool(bazarish::i2p::Router& router, std::size_t size, Shape shape)
    : router_(router)
    , size_(size)
    , shape_(std::move(shape))
{
}

void WarmDestPool::start()
{
    if (warmer_.joinable()) {
        return;
    }
    warmer_ = std::jthread([this](const std::stop_token& stop) { warmerLoop(stop); });
}

void WarmDestPool::stop()
{
    warmer_.request_stop();
}

std::shared_ptr<bazarish::i2p::Endpoint> WarmDestPool::acquire(const bazarish::i2p::Privacy privacy)
{
    std::shared_ptr<bazarish::i2p::Endpoint> dest;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        while (!ready_.empty()) {
            Warm warm = std::move(ready_.front());
            ready_.pop_front();
            if (warm.privacy == privacy && !warm.endpoint->lost()) {
                dest = std::move(warm.endpoint);
                break;
            }
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

void WarmDestPool::warmerLoop(const std::stop_token& stop)
{
    std::vector<Building> building;

    while (!stop.stop_requested()) {
        std::size_t toCreate = 0;
        std::size_t generation = 0;
        std::deque<Warm> unwanted;
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

        for (std::size_t i = 0; i < toCreate && !stop.stop_requested(); ++i) {
            try {
                const bazarish::i2p::EndpointConfig shape = shape_();
                auto endpoint = router_.createEndpoint(shape);
                if (endpoint) {
                    building.push_back({std::move(endpoint), std::chrono::steady_clock::now(),
                        generation, shape.privacy});
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
                    if (it->generation == generation_) {
                        ready_.push_back({std::move(it->endpoint), it->privacy});
                    }
                    warm = ready_.size();
                }
                bazarish::log::info("warm-pool: {} ready ({} warm, target {})",
                    shape_().label, warm, size_);
                it = building.erase(it);
            } else if (now - it->startedAt > buildTimeout_) {
                bazarish::log::warn("warm-pool: abandoning a dest that never warmed");
                it = building.erase(it);
            } else {
                ++it;
            }
        }

        std::unique_lock<std::mutex> lock(mutex_);
        (void)cv_.wait_for(lock, stop, building.empty() ? kIdlePoll : kBuildingPoll,
            [this]() { return refillWanted_; });
        refillWanted_ = false;
    }
}

}  // namespace bazarish::client
