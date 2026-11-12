// Bazarish project (c) 2026
#include "bazarish/TrafficShape.hpp"

#include "bazarish/Bytes.hpp"

#include <algorithm>
#include <climits>
#include <cmath>
#include <limits>
#include <numbers>
#include <stdexcept>

namespace bazarish::shape {

namespace {

constexpr int kMantissaBits = std::numeric_limits<double>::digits;
constexpr int kWordBits = sizeof(std::uint64_t) * CHAR_BIT;
constexpr double kBoxMullerScale = -2.0;
constexpr double kFullTurn = 2.0 * std::numbers::pi;
// Half a step past the integer keeps both ends of the unit interval out.
constexpr double kHalfStep = 0.5;

double logNormalValue(const double median, const double sigma, RandomSource& random)
{
    const double radius = std::sqrt(kBoxMullerScale * std::log(uniformOpen(random)));
    const double standard = radius * std::cos(kFullTurn * uniformOpen(random));
    return median * std::exp(sigma * standard);
}

const LogNormalPart& pickPart(const LogNormalMixture& shape, RandomSource& random)
{
    double total = 0;
    for (const LogNormalPart& part : shape.parts) {
        total += part.weight;
    }
    double point = uniformOpen(random) * total;
    for (const LogNormalPart& part : shape.parts) {
        if (point < part.weight) {
            return part;
        }
        point -= part.weight;
    }
    return shape.parts.back();
}

}  // namespace

std::uint64_t SystemRandom::next()
{
    std::uint64_t value = 0;
    for (const std::uint8_t byte : randomBytes(sizeof(std::uint64_t))) {
        value = (value << CHAR_BIT) | byte;
    }
    return value;
}

double uniformOpen(RandomSource& random)
{
    const std::uint64_t bits = random.next() >> (kWordBits - kMantissaBits);
    return (static_cast<double>(bits) + kHalfStep) / std::ldexp(1.0, kMantissaBits);
}

double draw(const LogNormal& shape, RandomSource& random)
{
    return drawAtLeast(shape, shape.min, random);
}

double drawAtLeast(const LogNormal& shape, const double floor, RandomSource& random)
{
    const double low = std::max(shape.min, floor);
    if (low > shape.max) {
        throw std::invalid_argument("a draw asked to land above its own ceiling");
    }
    for (;;) {
        const double value = logNormalValue(shape.median, shape.sigma, random);
        if (value >= low && value <= shape.max) {
            return value;
        }
    }
}

double draw(const Pareto& shape, RandomSource& random)
{
    for (;;) {
        const double value = shape.min / std::pow(uniformOpen(random), 1.0 / shape.alpha);
        if (value <= shape.max) {
            return value;
        }
    }
}

double draw(const LogNormalMixture& shape, RandomSource& random)
{
    for (;;) {
        const LogNormalPart& part = pickPart(shape, random);
        const double value = logNormalValue(part.median, part.sigma, random);
        if (value >= shape.min && value <= shape.max) {
            return value;
        }
    }
}

void validate(const LogNormalMixture& shape)
{
    if (shape.parts.empty()) {
        throw std::invalid_argument("a size mixture has at least one part");
    }
    if (!(shape.min < shape.max)) {
        throw std::invalid_argument("a size mixture's ceiling is above its floor");
    }
    for (const LogNormalPart& part : shape.parts) {
        if (!(part.weight > 0) || !(part.sigma > 0)) {
            throw std::invalid_argument("a part of a size mixture has a weight and a spread");
        }
        if (part.median < shape.min || part.median > shape.max) {
            throw std::invalid_argument("a part's median lies between the floor and the ceiling");
        }
    }
}

Pareto readPause()
{
    return {kReadAlpha, std::chrono::duration<double>(kReadMin).count(),
        std::chrono::duration<double>(kReadMax).count()};
}

Pareto embeddedCount()
{
    return {kEmbeddedAlpha, kEmbeddedMin, kEmbeddedMax + 1};
}

LogNormal inBurstGap()
{
    return {std::chrono::duration<double>(kInBurstGapMedian).count(), kInBurstGapSigma, 0,
        std::chrono::duration<double>(kInBurstGapMax).count()};
}

LogNormal decoyRequestBytes()
{
    return {kDecoyRequestMedianBytes, kDecoyRequestSigma, kDecoyRequestMinBytes,
        kDecoyRequestMaxBytes};
}

void ActivityState::userActed(const Clock::time_point at)
{
    lastInput_ = at;
    ++actions_;
}

Activity ActivityState::state(const Clock::time_point now, const bool exchanging) const
{
    if (exchanging) {
        return Activity::eActive;
    }
    const bool recent = lastInput_.has_value() && now - *lastInput_ < kInputIdleAfter;
    return windowActive_ && screenOn_ && recent ? Activity::eActive : Activity::eIdle;
}

std::vector<DecoyRequest> drawBurst(RandomSource& random)
{
    std::vector<DecoyRequest> burst;
    burst.push_back({false, static_cast<std::size_t>(draw(decoyRequestBytes(), random)),
        std::chrono::milliseconds(0)});
    const std::size_t embedded = static_cast<std::size_t>(
        std::min(std::floor(draw(embeddedCount(), random)), kEmbeddedMax));
    for (std::size_t i = 0; i < embedded; ++i) {
        const std::chrono::duration<double> gap(draw(inBurstGap(), random));
        burst.push_back({true, static_cast<std::size_t>(draw(decoyRequestBytes(), random)),
            std::chrono::duration_cast<std::chrono::milliseconds>(gap)});
    }
    return burst;
}

BurstPlan::BurstPlan(RandomSource& random, const Pareto readPause)
    : random_(random)
    , readPause_(readPause)
{
}

void BurstPlan::userActed(const Clock::time_point at)
{
    input_ = at;
}

void BurstPlan::burstEnded(const Clock::time_point at)
{
    if (phase_ == Phase::eDecoy) {
        read(at);
    }
}

std::optional<Clock::time_point> BurstPlan::readingUntil() const
{
    if (phase_ != Phase::eReading) {
        return std::nullopt;
    }
    return until_;
}

void BurstPlan::read(const Clock::time_point from)
{
    phase_ = Phase::eReading;
    since_ = from;
    until_ = from
        + std::chrono::duration_cast<Clock::duration>(
            std::chrono::duration<double>(draw(readPause_, random_)));
}

bool BurstPlan::realSince(
    const std::optional<Clock::time_point> lastReal, const Clock::time_point since)
{
    return lastReal.has_value() && *lastReal > since;
}

BurstStep BurstPlan::tick(const Clock::time_point now, const Activity activity,
    const bool exchanging, const std::optional<Clock::time_point> lastReal)
{
    const bool active = activity == Activity::eActive;
    const bool realNow = lastReal.has_value() && now - *lastReal < kInBurstGapMax;
    const auto start = [&]() {
        if (exchanging) {
            read(now);
            return BurstStep::eNothing;
        }
        if (realNow) {
            phase_ = Phase::eReal;
            since_ = now;
            return BurstStep::eNothing;
        }
        phase_ = Phase::eDecoy;
        since_ = now;
        return BurstStep::eDecoyBurst;
    };
    switch (phase_) {
        case Phase::eWaiting:
            if (active && realNow) {
                phase_ = Phase::eReal;
                since_ = now;
                return BurstStep::eNothing;
            }
            if (active && input_.has_value() && *input_ > since_) {
                return start();
            }
            return BurstStep::eNothing;
        case Phase::eReading:
            if (active && realSince(lastReal, since_)) {
                phase_ = Phase::eReal;
                since_ = now;
                return BurstStep::eNothing;
            }
            if (now < until_) {
                return BurstStep::eNothing;
            }
            if (!active) {
                phase_ = Phase::eWaiting;
                since_ = now;
                return BurstStep::eNothing;
            }
            return start();
        case Phase::eReal:
            if (!realNow) {
                read(now);
            }
            return BurstStep::eNothing;
        case Phase::eDecoy:
            return BurstStep::eNothing;
    }
    return BurstStep::eNothing;
}

}  // namespace bazarish::shape
