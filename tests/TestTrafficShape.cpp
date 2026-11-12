// Bazarish project (c) 2026
#include "bazarish/TrafficShape.hpp"

#include "TestUtil.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <optional>
#include <random>
#include <vector>

using namespace bazarish;
using namespace bazarish::shape;

namespace {

constexpr std::uint64_t kSeed = 20261112;
constexpr int kDraws = 40000;
// Relative slack on a median and on a tail fraction estimated from kDraws draws.
constexpr double kMedianSlack = 0.05;
constexpr double kTailSlack = 0.15;
constexpr std::chrono::milliseconds kTick{200};
constexpr std::chrono::hours kLongIdle{3};
constexpr std::chrono::seconds kIdleStep{1};
constexpr int kBurstRounds = 400;

class SeededRandom final : public RandomSource {
public:
    explicit SeededRandom(const std::uint64_t seed) : engine_(seed) {}
    std::uint64_t next() override { return engine_(); }

private:
    std::mt19937_64 engine_;
};

double medianOf(std::vector<double> values)
{
    std::sort(values.begin(), values.end());
    return values[values.size() / 2];
}

double fractionAbove(const std::vector<double>& values, const double point)
{
    const auto above = std::count_if(
        values.begin(), values.end(), [point](const double value) { return value > point; });
    return static_cast<double>(above) / static_cast<double>(values.size());
}

bool near(const double measured, const double expected, const double slack)
{
    return std::fabs(measured - expected) <= slack * expected;
}

void checkLogNormal()
{
    SeededRandom random(kSeed);
    const LogNormal gap = inBurstGap();
    std::vector<double> drawn;
    for (int i = 0; i < kDraws; ++i) {
        drawn.push_back(draw(gap, random));
    }
    CHECK(*std::min_element(drawn.begin(), drawn.end()) >= gap.min);
    CHECK(*std::max_element(drawn.begin(), drawn.end()) <= gap.max);
    CHECK(near(medianOf(drawn), gap.median, kMedianSlack));
    // One sigma above the median holds 15.9 % of an untruncated log-normal.
    const double oneSigma = gap.median * std::exp(gap.sigma);
    const double untruncatedAbove = 0.1587;
    CHECK(near(fractionAbove(drawn, oneSigma), untruncatedAbove, kTailSlack));

    const LogNormal request = decoyRequestBytes();
    std::vector<double> sizes;
    for (int i = 0; i < kDraws; ++i) {
        sizes.push_back(draw(request, random));
    }
    CHECK(*std::min_element(sizes.begin(), sizes.end()) >= kDecoyRequestMinBytes);
    CHECK(*std::max_element(sizes.begin(), sizes.end()) <= kDecoyRequestMaxBytes);
    CHECK(near(medianOf(sizes), kDecoyRequestMedianBytes, kMedianSlack));

    for (int i = 0; i < kDraws; ++i) {
        CHECK(drawAtLeast(request, kDecoyRequestMedianBytes, random) >= kDecoyRequestMedianBytes);
    }
    CHECK_THROWS(drawAtLeast(request, kDecoyRequestMaxBytes + 1, random));
}

void checkPareto()
{
    SeededRandom random(kSeed);
    const Pareto pause = readPause();
    std::vector<double> drawn;
    for (int i = 0; i < kDraws; ++i) {
        drawn.push_back(draw(pause, random));
    }
    CHECK(*std::min_element(drawn.begin(), drawn.end()) >= pause.min);
    CHECK(*std::max_element(drawn.begin(), drawn.end()) <= pause.max);
    const double untruncated = 1 - std::pow(pause.min / pause.max, pause.alpha);
    constexpr double kTailPoints[] = {2, 4, 10};
    for (const double times : kTailPoints) {
        const double point = pause.min * times;
        const double expected
            = (std::pow(pause.min / point, pause.alpha) - (1 - untruncated)) / untruncated;
        CHECK(near(fractionAbove(drawn, point), expected, kTailSlack));
    }

    std::vector<double> counts;
    for (int i = 0; i < kDraws; ++i) {
        counts.push_back(std::floor(draw(embeddedCount(), random)));
    }
    CHECK(*std::min_element(counts.begin(), counts.end()) >= kEmbeddedMin);
    CHECK(*std::max_element(counts.begin(), counts.end()) <= kEmbeddedMax + 1);
    const double secondCount = kEmbeddedMin + 1;
    const double moreThanOne = std::pow(kEmbeddedMin / secondCount, kEmbeddedAlpha);
    CHECK(near(fractionAbove(counts, kEmbeddedMin), moreThanOne, kTailSlack));
}

void checkMixture()
{
    SeededRandom random(kSeed);
    const double smallMedian = 1000;
    const double largeMedian = 100000;
    const double sigma = 0.3;
    const double ceiling = 1e6;
    const double smallWeight = 3;
    const double largeWeight = 1;
    const LogNormalMixture mixture{
        {{smallWeight, smallMedian, sigma}, {largeWeight, largeMedian, sigma}}, 1, ceiling};
    validate(mixture);
    std::vector<double> drawn;
    for (int i = 0; i < kDraws; ++i) {
        drawn.push_back(draw(mixture, random));
    }
    const double between = std::sqrt(smallMedian * largeMedian);
    CHECK(near(fractionAbove(drawn, between), largeWeight / (smallWeight + largeWeight),
        kTailSlack));
    CHECK_THROWS(validate(LogNormalMixture{{}, 1, ceiling}));
    CHECK_THROWS(validate(LogNormalMixture{{{1, smallMedian, sigma}}, ceiling, 1}));
    CHECK_THROWS(validate(LogNormalMixture{{{1, ceiling * 2, sigma}}, 1, ceiling}));
    CHECK_THROWS(validate(LogNormalMixture{{{0, smallMedian, sigma}}, 1, ceiling}));
    CHECK_THROWS(validate(LogNormalMixture{{{1, smallMedian, 0}}, 1, ceiling}));
}

void checkBurstShape()
{
    SeededRandom random(kSeed);
    std::size_t resources = 0;
    for (int round = 0; round < kBurstRounds; ++round) {
        const std::vector<DecoyRequest> burst = drawBurst(random);
        CHECK(burst.size() >= 2);
        CHECK(burst.size() <= static_cast<std::size_t>(kEmbeddedMax) + 1);
        CHECK(!burst.front().resource);
        CHECK(burst.front().after.count() == 0);
        for (std::size_t i = 1; i < burst.size(); ++i) {
            CHECK(burst[i].resource);
            CHECK(burst[i].after <= kInBurstGapMax);
        }
        for (const DecoyRequest& request : burst) {
            CHECK(request.bytes >= static_cast<std::size_t>(kDecoyRequestMinBytes));
            CHECK(request.bytes <= static_cast<std::size_t>(kDecoyRequestMaxBytes));
        }
        resources += burst.size() - 1;
    }
    CHECK(resources > static_cast<std::size_t>(kBurstRounds));
}

void checkActivity()
{
    const Clock::time_point start = Clock::now();
    ActivityState state;
    CHECK(state.state(start, false) == Activity::eIdle);
    CHECK(state.state(start, true) == Activity::eActive);
    state.windowActive(true);
    CHECK(state.state(start, false) == Activity::eIdle);
    state.userActed(start);
    CHECK(state.actions() == 1);
    CHECK(state.state(start, false) == Activity::eActive);
    CHECK(state.state(start + kInputIdleAfter - kTick, false) == Activity::eActive);
    CHECK(state.state(start + kInputIdleAfter, false) == Activity::eIdle);
    state.screenOn(false);
    CHECK(state.state(start, false) == Activity::eIdle);
    state.screenOn(true);
    state.windowActive(false);
    CHECK(state.state(start, false) == Activity::eIdle);
    state.windowActive(true);
    CHECK(state.state(start, false) == Activity::eActive);
}

struct Run {
    std::vector<Clock::time_point> bursts;
};

// Ticks a plan through a span with the user acting at the start and going idle at goIdle.
Run simulate(const std::uint64_t seed, const Clock::time_point start,
    const std::optional<Clock::time_point> goIdle, const Clock::duration span)
{
    SeededRandom random(seed);
    BurstPlan plan(random, readPause());
    Run run;
    plan.userActed(start);
    for (Clock::time_point now = start; now < start + span; now += kTick) {
        const bool idle = goIdle.has_value() && now >= *goIdle;
        const Activity activity = idle ? Activity::eIdle : Activity::eActive;
        if (plan.tick(now, activity, false, std::nullopt) == BurstStep::eDecoyBurst) {
            run.bursts.push_back(now);
            plan.burstEnded(now + kTick);
        }
    }
    return run;
}

void checkBurstPlan()
{
    const Clock::time_point start = Clock::now();
    {
        SeededRandom random(kSeed);
        BurstPlan plan(random, readPause());
        for (Clock::time_point now = start; now < start + kLongIdle; now += kIdleStep) {
            CHECK(plan.tick(now, Activity::eIdle, false, std::nullopt) == BurstStep::eNothing);
        }
        CHECK(plan.tick(start + kLongIdle, Activity::eActive, false, std::nullopt)
            == BurstStep::eNothing);
        plan.userActed(start + kLongIdle);
        CHECK(plan.tick(start + kLongIdle, Activity::eActive, false, std::nullopt)
            == BurstStep::eDecoyBurst);
        CHECK(plan.tick(start + kLongIdle, Activity::eActive, false, std::nullopt)
            == BurstStep::eNothing);
        plan.burstEnded(start + kLongIdle);
        const std::optional<Clock::time_point> until = plan.readingUntil();
        CHECK(until.has_value());
        CHECK(*until - (start + kLongIdle) >= kReadMin);
        CHECK(*until - (start + kLongIdle) <= kReadMax);
    }

    {
        SeededRandom random(kSeed);
        BurstPlan plan(random, readPause());
        plan.userActed(start);
        CHECK(plan.tick(start, Activity::eActive, false, std::nullopt) == BurstStep::eDecoyBurst);
        plan.burstEnded(start);
        const Clock::time_point until = *plan.readingUntil();
        const Clock::time_point real = start + (until - start) / 2;
        CHECK(plan.tick(real, Activity::eActive, false, real) == BurstStep::eNothing);
        CHECK(!plan.reading());
        CHECK(plan.tick(real + kInBurstGapMax - kTick, Activity::eActive, false, real)
            == BurstStep::eNothing);
        CHECK(!plan.reading());
        CHECK(plan.tick(real + kInBurstGapMax, Activity::eActive, false, real)
            == BurstStep::eNothing);
        CHECK(plan.reading());
        const Clock::time_point next = *plan.readingUntil();
        CHECK(plan.tick(next, Activity::eActive, true, real) == BurstStep::eNothing);
        CHECK(plan.reading());
        CHECK(*plan.readingUntil() > next);
    }

    const Clock::duration span = std::chrono::hours(1);
    const Run active = simulate(kSeed, start, std::nullopt, span);
    CHECK(active.bursts.size() > 2);
    const Clock::time_point idleAt = active.bursts[2] + (active.bursts[3] - active.bursts[2]) / 2;
    const Run quieted = simulate(kSeed, start, idleAt, span);
    CHECK(quieted.bursts.size() == 3);
    for (std::size_t i = 0; i < quieted.bursts.size(); ++i) {
        CHECK(quieted.bursts[i] == active.bursts[i]);
    }

    for (std::uint64_t seed = 0; seed < static_cast<std::uint64_t>(kBurstRounds); ++seed) {
        const Run run = simulate(seed, start, std::nullopt, span);
        CHECK(run.bursts.size() > 1);
        const Clock::time_point idle = run.bursts[0] + (run.bursts[1] - run.bursts[0]) / 2;
        const Run gone = simulate(seed, start, idle, span);
        CHECK(gone.bursts.size() == 1);
        CHECK(gone.bursts.front() == run.bursts.front());
    }
}

}  // namespace

int main()
{
    checkLogNormal();
    checkPareto();
    checkMixture();
    checkBurstShape();
    checkActivity();
    checkBurstPlan();
    std::printf("TestTrafficShape ok\n");
    return 0;
}
