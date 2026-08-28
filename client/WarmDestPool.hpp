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

// A small pool of pre-built, unattributed transient outbound I2P destinations kept
// warm (their tunnels already built) so whoever needs one - a contact-card fetch,
// an alias resolve, an outgoing message - grabs a ready one instead of paying the
// cold tunnel-build latency (seconds). A spare belongs to nobody until it is taken
// and is never handed out twice; what the taker does with it afterwards is the
// taker's business: a lookup drops it when the answer is in, a delivery holds it
// for one term and one correspondent.
//
// The client's mirror of the server's warm pool, but deliberately simple: a fixed
// target size (no demand-driven sizing) and a small tunnel quantity. Best-effort -
// a slow or failing build (a router that cannot yet build tunnels) never blocks
// acquire(), which just returns nullptr so the caller builds a fresh dest cold.
class WarmDestPool {
public:
    WarmDestPool(bazarish::i2p::Router& router, std::size_t size, int tunnelQuantity);
    ~WarmDestPool();

    void start();
    void stop();

    // Drops every spare, warm or still building, and builds the pool again. Used
    // when the tunnel profile changes: a spare built at the old hop length would
    // otherwise be handed out long after the user asked for a different one.
    void flush();

    // A warm endpoint, or nullptr when none is ready (the caller then builds a
    // fresh dest cold). It is the caller's from here and is never returned to the
    // pool; the pool starts building a replacement at once.
    std::shared_ptr<bazarish::i2p::Endpoint> acquire();

private:
    void warmerLoop();
    // A destination still warming (its tunnels building), with the time it started so
    // a never-ready build can be abandoned.
    struct Building {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        std::chrono::steady_clock::time_point startedAt;
        std::size_t generation = 0;
    };

    bazarish::i2p::Router& router_;
    // A spare was taken (or thrown away): build the replacement now rather than
    // at the next tick. Guarded by mutex_.
    bool refillWanted_ = false;
    const std::size_t size_;
    const int tunnelQuantity_;
    // How long a freshly created dest is given to warm before it is abandoned.
    const std::chrono::seconds buildTimeout_{120};

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::shared_ptr<bazarish::i2p::Endpoint>> ready_;  // warm, unused
    // Bumped by flush(). A destination that was already building under an older
    // generation is dropped rather than promoted.
    std::size_t generation_ = 0;
    std::atomic<bool> running_{false};
    std::thread warmer_;
};

}  // namespace bazarish::client
