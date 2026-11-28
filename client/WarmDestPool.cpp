// Bazarish project (c) 2026
#include "WarmDestPool.hpp"

#include <bazarish/Log.hpp>
#include <bazarish/StopWake.hpp>

#include <algorithm>
#include <vector>

namespace bazarish::client {

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

std::optional<std::string> WarmDestPool::failure() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return failure_;
}

void WarmDestPool::stateChanged()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        stateChanged_ = true;
    }
    cv_.notify_all();
}

std::string WarmDestPool::whyNotWarm(const bazarish::i2p::Endpoint& endpoint) const
{
    const std::string host = endpoint.routingHost();
    for (const bazarish::i2p::LocalDestination& held : router_.localDestinations()) {
        if (held.host != host) {
            continue;
        }
        return std::to_string(held.inboundTunnels) + " inbound and "
            + std::to_string(held.outboundTunnels) + " outbound tunnel(s) built"
            + (held.closing ? ", its tunnel pool closing" : "");
    }
    return "the router no longer lists it";
}

void WarmDestPool::warmerLoop(const std::stop_token& stop)
{
    const StopWake wake(stop, mutex_, cv_);
    std::vector<Building> building;
    bool refillAsked = true;

    while (!stop.stop_requested()) {
        std::size_t toCreate = 0;
        std::size_t generation = 0;
        std::deque<Warm> unwanted;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            generation = generation_;
            if (!wanted_) {
                unwanted.swap(ready_);
            }
            if (refillAsked) {
                failure_.reset();
            }
        }
        std::erase_if(building, [generation](const Building& item) {
            return item.generation != generation;
        });
        unwanted.clear();
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            const std::size_t have = ready_.size() + building.size();
            toCreate = wanted_ && !failure_.has_value() && size_ > have ? size_ - have : 0;
        }

        for (std::size_t i = 0; i < toCreate && !stop.stop_requested(); ++i) {
            try {
                const bazarish::i2p::EndpointConfig shape = shape_();
                std::shared_ptr<bazarish::i2p::Endpoint> endpoint = router_.createEndpoint(shape);
                auto watch = std::make_unique<bazarish::i2p::EndpointWatch>(
                    *endpoint, [this]() { stateChanged(); });
                building.push_back({std::move(endpoint), std::move(watch),
                    std::chrono::steady_clock::now(), generation, shape.privacy});
            } catch (const std::exception& error) {
                bazarish::log::warn(
                    "warm-pool: a destination was not built; the pool waits to be asked again: {}",
                    error.what());
                const std::lock_guard<std::mutex> lock(mutex_);
                failure_ = error.what();
                break;
            }
        }

        const auto now = std::chrono::steady_clock::now();
        std::optional<std::chrono::steady_clock::time_point> giveUpAt;
        for (auto it = building.begin(); it != building.end();) {
            if (it->endpoint->ready()) {
                std::size_t warm = 0;
                {
                    const std::lock_guard<std::mutex> lock(mutex_);
                    if (it->generation == generation_) {
                        ready_.push_back({it->endpoint, it->privacy});
                    }
                    warm = ready_.size();
                }
                bazarish::log::info("warm-pool: {} ready ({} warm, target {})",
                    shape_().label, warm, size_);
                it = building.erase(it);
            } else if (it->endpoint->lost()) {
                bazarish::log::warn("warm-pool: the transport took a destination down before it warmed");
                it = building.erase(it);
            } else if (now - it->startedAt >= buildTimeout_) {
                bazarish::log::warn("warm-pool: stopping a destination not warm after {} s: {}",
                    buildTimeout_.count(), whyNotWarm(*it->endpoint));
                it->endpoint->stop();
                it = building.erase(it);
            } else {
                const auto at = it->startedAt + buildTimeout_;
                giveUpAt = giveUpAt.has_value() ? std::min(*giveUpAt, at) : at;
                ++it;
            }
        }

        std::unique_lock<std::mutex> lock(mutex_);
        const auto woken = [this]() { return refillWanted_ || stateChanged_; };
        if (giveUpAt.has_value()) {
            (void)cv_.wait_until(lock, stop, *giveUpAt, woken);
        } else {
            (void)cv_.wait(lock, stop, woken);
        }
        refillAsked = refillWanted_;
        refillWanted_ = false;
        stateChanged_ = false;
    }
}

}  // namespace bazarish::client
