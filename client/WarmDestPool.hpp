// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace bazarish::client {

class WarmDestPool {
public:
    // The shape is asked for each destination built, so a privacy change reaches the next one.
    using Shape = std::function<bazarish::i2p::EndpointConfig()>;
    WarmDestPool(bazarish::i2p::Router& router, std::size_t size, Shape shape);
    ~WarmDestPool();

    void start();
    void stop();

    void flush();
    void setWanted(bool wanted);

    // Only a destination built with this privacy: one from before a change is not handed out.
    std::shared_ptr<bazarish::i2p::Endpoint> acquire(bazarish::i2p::Privacy privacy);

private:
    void warmerLoop();
    struct Building {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
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
    bool wanted_ = true;
    const std::size_t size_;
    const Shape shape_;
    const std::chrono::seconds buildTimeout_{120};

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Warm> ready_;
    std::size_t generation_ = 0;
    std::atomic<bool> running_{false};
    std::thread warmer_;
};

}  // namespace bazarish::client
