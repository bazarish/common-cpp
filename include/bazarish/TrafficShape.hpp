// Bazarish project (c) 2026
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace bazarish::shape {

class RandomSource {
public:
    virtual ~RandomSource() = default;
    virtual std::uint64_t next() = 0;
};

class SystemRandom final : public RandomSource {
public:
    std::uint64_t next() override;
};

// Uniform in (0, 1).
double uniformOpen(RandomSource& random);

// A draw outside [min, max] is drawn again.
struct LogNormal {
    double median = 0;
    double sigma = 0;
    double min = 0;
    double max = 0;
};

struct Pareto {
    double alpha = 0;
    double min = 0;
    double max = 0;
};

struct LogNormalPart {
    double weight = 0;
    double median = 0;
    double sigma = 0;
};

struct LogNormalMixture {
    std::vector<LogNormalPart> parts;
    double min = 0;
    double max = 0;
};

double draw(const LogNormal& shape, RandomSource& random);
double drawAtLeast(const LogNormal& shape, double floor, RandomSource& random);
double draw(const Pareto& shape, RandomSource& random);
double draw(const LogNormalMixture& shape, RandomSource& random);

// Throws when a draw could not land inside the bounds often enough to end.
void validate(const LogNormalMixture& shape);

using Clock = std::chrono::steady_clock;

// Starting values from SURGE (Barford and Crovella, 1998), not fitted to a capture.
inline constexpr double kEmbeddedAlpha = 2.4;
inline constexpr double kEmbeddedMin = 1;
inline constexpr double kEmbeddedMax = 30;
inline constexpr double kReadAlpha = 1.5;
inline constexpr std::chrono::seconds kReadMin{3};
inline constexpr std::chrono::seconds kReadMax{600};
inline constexpr std::chrono::milliseconds kInBurstGapMedian{80};
inline constexpr double kInBurstGapSigma = 1.0;
inline constexpr std::chrono::milliseconds kInBurstGapMax{2000};
inline constexpr double kDecoyRequestMedianBytes = 600;
inline constexpr double kDecoyRequestSigma = 0.45;
inline constexpr double kDecoyRequestMinBytes = 300;
inline constexpr double kDecoyRequestMaxBytes = 1500;

// Chrome's HTTP/1.1 connections per host (max_sockets_per_group, client_socket_pool_manager.cc).
inline constexpr std::size_t kMaxConnectionsPerHost = 6;

inline constexpr std::chrono::seconds kInputIdleAfter{120};

Pareto readPause();
Pareto embeddedCount();
LogNormal inBurstGap();
LogNormal decoyRequestBytes();

enum class Activity { eActive, eIdle };

// Focus alone is not an action: only input moves the clock that keeps a window active.
class ActivityState {
public:
    void windowActive(bool active) { windowActive_ = active; }
    void screenOn(bool on) { screenOn_ = on; }
    void userActed(Clock::time_point at);

    Activity state(Clock::time_point now, bool exchanging) const;
    std::uint64_t actions() const { return actions_; }

private:
    bool windowActive_ = false;
    bool screenOn_ = true;
    std::optional<Clock::time_point> lastInput_;
    std::uint64_t actions_ = 0;
};

struct DecoyRequest {
    bool resource = false;
    std::size_t bytes = 0;
    std::chrono::milliseconds after{0};
};

// A page, then the resources it embeds, each asked a short gap after the one before.
std::vector<DecoyRequest> drawBurst(RandomSource& random);

enum class BurstStep { eNothing, eDecoyBurst };

// Going idle sends nothing: the read pause already drawn runs out and no burst follows.
class BurstPlan {
public:
    BurstPlan(RandomSource& random, Pareto readPause);

    void userActed(Clock::time_point at);
    void burstEnded(Clock::time_point at);
    BurstStep tick(Clock::time_point now, Activity activity, bool exchanging,
        std::optional<Clock::time_point> lastReal);

    bool reading() const { return phase_ == Phase::eReading; }
    bool waiting() const { return phase_ == Phase::eWaiting; }
    std::optional<Clock::time_point> readingUntil() const;

private:
    enum class Phase { eWaiting, eReading, eDecoy, eReal };

    void read(Clock::time_point from);
    static bool realSince(std::optional<Clock::time_point> lastReal, Clock::time_point since);

    RandomSource& random_;
    Pareto readPause_;
    Phase phase_ = Phase::eWaiting;
    Clock::time_point since_{};
    Clock::time_point until_{};
    std::optional<Clock::time_point> input_;
};

}  // namespace bazarish::shape
