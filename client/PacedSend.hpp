// Bazarish project (c) 2026
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <string>
#include <thread>

namespace bazarish::client {

// How a long stream is written over I2P: a chunk at a time, never more than a cap left unsent.
inline constexpr std::size_t kPacedChunkBytes = 64 * 1024;
inline constexpr std::size_t kPacedQueueCap = 128 * 1024;
inline constexpr std::chrono::milliseconds kPacedQueuePoll{100};
inline constexpr std::size_t kDrainProbeBytes = 64;

// What has left this end: written less what still waits in the stream.
inline std::uint64_t onTheWire(const std::uint64_t written, const std::size_t queued)
{
    return written > queued ? written - queued : 0;
}

// Waits while more than the cap is unsent; false when told to stop meanwhile.
template <class Stream>
bool waitForRoom(Stream& stream, const std::uint64_t written,
    const std::function<bool()>& stopped, const std::function<void(std::uint64_t)>& progress)
{
    while (stream.pendingBytes() > kPacedQueueCap) {
        if (stopped()) {
            return false;
        }
        if (progress) {
            progress(onTheWire(written, stream.pendingBytes()));
        }
        std::this_thread::sleep_for(kPacedQueuePoll);
    }
    if (progress) {
        progress(onTheWire(written, stream.pendingBytes()));
    }
    return true;
}

enum class DrainOutcome { eClosed, eBroken, eTimedOut };

// After the last byte, waits for the other end to close: that it did is what says it all arrived.
template <class Stream>
DrainOutcome drainUntilClosed(Stream& stream, const std::uint64_t written,
    const std::chrono::seconds limit, const std::function<void(std::uint64_t)>& progress,
    std::string& brokenBecause)
{
    std::array<unsigned char, kDrainProbeBytes> drain{};
    const auto until = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < until) {
        if (progress) {
            progress(onTheWire(written, stream.pendingBytes()));
        }
        try {
            if (stream.readSome(drain) == 0) {
                return DrainOutcome::eClosed;
            }
        } catch (const std::exception& error) {
            brokenBecause = error.what();
            return DrainOutcome::eBroken;
        }
    }
    return DrainOutcome::eTimedOut;
}

}  // namespace bazarish::client
