// Bazarish project (c) 2026
#pragma once

#include "bazarish/GatewayProtocol.hpp"

#include <bazarish/Bytes.hpp>

#include <cstddef>
#include <cstdint>
#include <mutex>

namespace bazarish::gateway {

class StreamBook {
public:

    std::size_t room() const;
    void wrote(const void* data, std::size_t size);
    std::uint64_t sent() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return sent_;
    }
    void peerCredited(std::uint64_t total);
    std::uint64_t credited() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return credited_;
    }
    std::size_t pending() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<std::size_t>(sent_ - credited_);
    }

    Bytes replay(std::uint64_t peerReceived);

    void finishSending()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        finishedSending_ = true;
    }
    bool finishedSending() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return finishedSending_;
    }

    void tookIn(std::size_t size);
    std::uint64_t received() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return received_;
    }
    void consumed(std::size_t size);
    std::uint64_t consumedTotal() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return consumed_;
    }

    void peerFinished()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        peerFinished_ = true;
    }
    bool peerHasFinished() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return peerFinished_;
    }

private:
    mutable std::mutex mutex_;
    std::uint64_t sent_ = 0;
    std::uint64_t credited_ = 0;
    std::uint64_t retainedFrom_ = 0;
    Bytes retained_;
    bool finishedSending_ = false;

    std::uint64_t received_ = 0;
    std::uint64_t consumed_ = 0;
    bool peerFinished_ = false;
};

}  // namespace bazarish::gateway
