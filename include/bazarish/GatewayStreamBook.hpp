// Bazarish project (c) 2026
#pragma once

#include "bazarish/GatewayProtocol.hpp"

#include <bazarish/Bytes.hpp>

#include <cstddef>
#include <cstdint>
#include <mutex>

namespace bazarish::gateway {

// What one stream owes and is owed, in both directions. It is the whole of the
// durability mechanism: one cumulative count per direction, and the bytes not
// yet known to have arrived.
//
// Under a flow is one TCP socket, which does not reorder and does not lose in
// the middle. The only way a stream loses anything is a truncation when the
// socket dies, and a truncation is what a cumulative count repairs. Sequence
// numbers and selective acknowledgement would solve reordering and holes,
// neither of which can happen here.
class StreamBook {
public:
    // --- what this side sends ---

    // Room left in the window. A writer keeps its queue inside this.
    std::size_t room() const;
    // Throws when it would overrun the window, which is a caller that ignored
    // room() rather than a peer doing anything wrong.
    void wrote(const void* data, std::size_t size);
    std::uint64_t sent() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return sent_;
    }
    // What the peer says it has consumed. Cumulative and never backwards, so a
    // credit lost with a socket costs nothing: the next one says the same
    // thing, only more of it.
    void peerCredited(std::uint64_t total);
    std::uint64_t credited() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return credited_;
    }
    // Bytes handed over that have not left this device yet.
    std::size_t pending() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<std::size_t>(sent_ - credited_);
    }

    // After a socket died: what the peer says it received decides what goes out
    // again. Everything below it is dropped, everything above it is returned in
    // order, and it must be sent before any new data on this stream.
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

    // --- what this side receives ---

    // Throws when the peer sent more than the window it was granted.
    void tookIn(std::size_t size);
    std::uint64_t received() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return received_;
    }
    // The application read them, which is what a credit says.
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
    // A reader thread fills the send side while the socket thread credits it,
    // and the receive side is the other way round. One lock, because the work
    // under it is arithmetic.
    mutable std::mutex mutex_;
    std::uint64_t sent_ = 0;
    std::uint64_t credited_ = 0;
    // The offset in the stream of the first byte still held, which is what
    // makes the retained bytes a window rather than a transcript.
    std::uint64_t retainedFrom_ = 0;
    Bytes retained_;
    bool finishedSending_ = false;

    std::uint64_t received_ = 0;
    std::uint64_t consumed_ = 0;
    bool peerFinished_ = false;
};

}  // namespace bazarish::gateway
