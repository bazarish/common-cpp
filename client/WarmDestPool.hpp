// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

namespace bazarish::client {

class WarmDestPool {
public:
    WarmDestPool(bazarish::i2p::Router& router, std::size_t size, int tunnelQuantity);
    ~WarmDestPool();

    void start();
    void stop();

    void flush();

    std::shared_ptr<bazarish::i2p::Endpoint> acquire();

private:
    void warmerLoop();
    struct Building {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        std::chrono::steady_clock::time_point startedAt;
        std::size_t generation = 0;
    };

    bazarish::i2p::Router& router_;
    bool refillWanted_ = false;
    const std::size_t size_;
    const int tunnelQuantity_;
    const std::chrono::seconds buildTimeout_{120};

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::shared_ptr<bazarish::i2p::Endpoint>> ready_;
    std::size_t generation_ = 0;
    std::atomic<bool> running_{false};
    std::thread warmer_;
};

}  // namespace bazarish::client
