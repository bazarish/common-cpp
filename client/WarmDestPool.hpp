// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>

namespace bazarish::client {

class WarmDestPool {
public:
    // The shape is asked for each destination built, so a privacy change reaches the next one.
    using Shape = std::function<bazarish::i2p::EndpointConfig()>;
    WarmDestPool(bazarish::i2p::Router& router, std::size_t size, Shape shape);

    void start();
    void stop();

    void flush();
    void setWanted(bool wanted);

    // Only a destination built with this privacy: one from before a change is not handed out.
    std::shared_ptr<bazarish::i2p::Endpoint> acquire(bazarish::i2p::Privacy privacy);

    // Why the last build failed; the pool builds again only once asked to refill.
    std::optional<std::string> failure() const;

private:
    void warmerLoop(const std::stop_token& stop);
    void stateChanged();
    std::string whyNotWarm(const bazarish::i2p::Endpoint& endpoint) const;
    struct Building {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        std::unique_ptr<bazarish::i2p::EndpointWatch> watch;
        std::chrono::steady_clock::time_point startedAt;
        std::size_t generation = 0;
        bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
    };
    struct Warm {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
    };

    bazarish::i2p::Router& router_;
    bool refillWanted_ = false;
    bool stateChanged_ = false;
    bool wanted_ = true;
    std::optional<std::string> failure_;
    const std::size_t size_;
    const Shape shape_;
    const std::chrono::seconds buildTimeout_{120};

    mutable std::mutex mutex_;
    std::condition_variable_any cv_;
    std::deque<Warm> ready_;
    std::size_t generation_ = 0;
    std::jthread warmer_;
};

}  // namespace bazarish::client
