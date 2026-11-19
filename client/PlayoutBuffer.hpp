// Bazarish project (c) 2026
#pragma once
#include <bazarish/Bytes.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>

namespace bazarish {

class PlayoutBuffer {
public:
    enum class Kind {
        eNothing,
        eFrame,
        eLost,
    };
    struct Next {
        Kind kind = Kind::eNothing;
        Bytes opus;
    };
    struct Counts {
        std::uint64_t underruns = 0;
        std::uint64_t late = 0;
        std::uint64_t dropped = 0;
    };

    PlayoutBuffer(std::size_t targetFrames, std::size_t limitFrames, std::uint64_t concealLimit);

    void put(std::uint64_t sequence, Bytes opus);
    // Called once per frame period; a frame that is not there in time is played as lost.
    Next take();
    Counts counts() const;
    std::size_t depth() const;

private:
    mutable std::mutex mutex_;
    const std::size_t targetFrames_;
    const std::size_t limitFrames_;
    const std::uint64_t concealLimit_;
    std::map<std::uint64_t, Bytes> frames_;
    bool filling_ = true;
    bool havePlayed_ = false;
    std::uint64_t lastPlayed_ = 0;
    Counts counts_;
};

class GapHistogram {
public:
    static constexpr std::size_t kLongestMs = 1000;
    struct Summary {
        std::uint64_t samples = 0;
        std::uint64_t medianMs = 0;
        std::uint64_t p99Ms = 0;
        std::uint64_t maxMs = 0;
    };

    void add(std::uint64_t gapMs);
    Summary summary() const;

private:
    std::array<std::uint64_t, kLongestMs + 1> buckets_{};
    std::uint64_t samples_ = 0;
    std::uint64_t maxMs_ = 0;
};

}  // namespace bazarish
