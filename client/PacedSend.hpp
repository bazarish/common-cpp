// Bazarish project (c) 2026
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <string>

namespace bazarish::client {

inline constexpr std::size_t kPacedChunkBytes = 64 * 1024;
inline constexpr std::size_t kDrainProbeBytes = 64;

inline std::uint64_t onTheWire(const std::uint64_t written, const std::size_t queued)
{
    return written > queued ? written - queued : 0;
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
