// Bazarish project (c) 2026
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace bazarish::i2p {

struct RawPath {
    std::uint32_t outboundTunnel = 0;
    std::array<std::uint8_t, 32> leaseGateway{};
    std::uint32_t leaseTunnel = 0;

    auto operator<=>(const RawPath&) const = default;
};

class RawPathChooser {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr std::chrono::milliseconds kProbeInterval{100};
    static constexpr std::chrono::milliseconds kProbeTimeout{2000};
    static constexpr std::chrono::milliseconds kSwitchMargin{30};
    static constexpr int kSmoothing = 4;

    struct Probe {
        std::uint64_t id = 0;
        RawPath path;
    };

    RawPathChooser();

    void offer(const std::vector<RawPath>& paths);
    bool probeDue(Clock::time_point now) const;
    std::optional<Probe> probe(Clock::time_point now);
    bool echoed(std::uint64_t id, Clock::time_point now);

    std::optional<RawPath> chosen() const;
    std::optional<std::chrono::milliseconds> roundTrip(const RawPath& path) const;

private:
    struct Score {
        double roundTripMs = 0.0;
        bool measured = false;
        Clock::time_point probedAt{};
    };
    struct Sent {
        RawPath path;
        Clock::time_point at;
    };

    void measure(const RawPath& path, std::chrono::milliseconds sample);
    void expire(Clock::time_point now);
    void choose();

    std::map<RawPath, Score> scores_;
    std::map<std::uint64_t, Sent> sent_;
    std::optional<RawPath> chosen_;
    std::uint64_t nextId_;
    Clock::time_point nextProbe_{};
    bool chosenNext_ = false;
};

}  // namespace bazarish::i2p
