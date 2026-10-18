// Bazarish project (c) 2026
#include "bazarish/RawPathChooser.hpp"

#include "TestUtil.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <vector>

using namespace bazarish::i2p;
using std::chrono::milliseconds;

namespace {

using Clock = RawPathChooser::Clock;

constexpr milliseconds kStep{10};

RawPath pathOf(const std::uint32_t tunnel)
{
    RawPath path;
    path.outboundTunnel = tunnel;
    return path;
}

std::vector<RawPath> pathsOf(const std::vector<std::uint32_t>& tunnels)
{
    std::vector<RawPath> paths;
    for (const std::uint32_t tunnel : tunnels) {
        paths.push_back(pathOf(tunnel));
    }
    return paths;
}

// A path missing from the map loses every probe.
void run(RawPathChooser& chooser, Clock::time_point& now,
    const std::map<std::uint32_t, int>& roundTripMs, const milliseconds span)
{
    std::multimap<Clock::time_point, std::uint64_t> echoes;
    const Clock::time_point end = now + span;
    for (; now < end; now += kStep) {
        while (!echoes.empty() && echoes.begin()->first <= now) {
            CHECK(chooser.echoed(echoes.begin()->second, now));
            echoes.erase(echoes.begin());
        }
        if (!chooser.probeDue(now)) {
            continue;
        }
        const auto probe = chooser.probe(now);
        CHECK(probe.has_value());
        const auto found = roundTripMs.find(probe->path.outboundTunnel);
        if (found != roundTripMs.end()) {
            echoes.emplace(now + milliseconds(found->second), probe->id);
        }
    }
}

std::uint32_t chosenTunnel(const RawPathChooser& chooser)
{
    CHECK(chooser.chosen().has_value());
    return chooser.chosen()->outboundTunnel;
}

void nothingOfferedNothingProbed()
{
    RawPathChooser chooser;
    const Clock::time_point now = Clock::now();
    CHECK(chooser.probeDue(now));
    CHECK(!chooser.probe(now).has_value());
    CHECK(!chooser.probeDue(now));
    CHECK(chooser.probeDue(now + RawPathChooser::kProbeInterval));
    CHECK(!chooser.chosen().has_value());
}

void everyPathIsProbedBeforeAnyRepeats()
{
    RawPathChooser chooser;
    chooser.offer(pathsOf({1, 2, 3}));
    Clock::time_point now = Clock::now();
    std::map<std::uint32_t, int> seen;
    for (int i = 0; i < 3; ++i) {
        const auto probe = chooser.probe(now);
        CHECK(probe.has_value());
        ++seen[probe->path.outboundTunnel];
        now += RawPathChooser::kProbeInterval;
    }
    CHECK(seen.size() == 3);
    CHECK(!chooser.chosen().has_value());
}

void theFastestPathIsChosen()
{
    RawPathChooser chooser;
    chooser.offer(pathsOf({1, 2, 3}));
    Clock::time_point now = Clock::now();
    run(chooser, now, {{1, 400}, {2, 150}, {3, 300}}, milliseconds(3000));
    CHECK(chosenTunnel(chooser) == 2);
    const auto roundTrip = chooser.roundTrip(pathOf(2));
    CHECK(roundTrip.has_value());
    CHECK(roundTrip.value() >= milliseconds(150));
    CHECK(roundTrip.value() < milliseconds(150) + kStep);
}

void aSmallGainDoesNotMoveTheCall()
{
    RawPathChooser chooser;
    chooser.offer(pathsOf({1, 2}));
    Clock::time_point now = Clock::now();
    run(chooser, now, {{1, 200}, {2, 180}}, milliseconds(3000));
    CHECK(chosenTunnel(chooser) == 1);
    run(chooser, now, {{1, 200}, {2, 100}}, milliseconds(3000));
    CHECK(chosenTunnel(chooser) == 2);
}

void aPathThatStopsAnsweringIsLeft()
{
    RawPathChooser chooser;
    chooser.offer(pathsOf({1, 2}));
    Clock::time_point now = Clock::now();
    run(chooser, now, {{1, 100}, {2, 250}}, milliseconds(3000));
    CHECK(chosenTunnel(chooser) == 1);
    run(chooser, now, {{2, 250}}, milliseconds(5000));
    CHECK(chosenTunnel(chooser) == 2);
}

void aChosenPathThatIsGoneIsReplaced()
{
    RawPathChooser chooser;
    chooser.offer(pathsOf({1, 2, 3}));
    Clock::time_point now = Clock::now();
    run(chooser, now, {{1, 100}, {2, 300}, {3, 200}}, milliseconds(3000));
    CHECK(chosenTunnel(chooser) == 1);
    chooser.offer(pathsOf({2, 3}));
    CHECK(chosenTunnel(chooser) == 3);
    chooser.offer(pathsOf({4}));
    CHECK(!chooser.chosen().has_value());
}

void aPathThatNeverAnsweredIsNeverChosen()
{
    RawPathChooser chooser;
    chooser.offer(pathsOf({1, 2}));
    Clock::time_point now = Clock::now();
    run(chooser, now, {}, milliseconds(5000));
    CHECK(!chooser.chosen().has_value());
    run(chooser, now, {{2, 900}}, milliseconds(3000));
    CHECK(chosenTunnel(chooser) == 2);
}

void theChosenPathGetsEveryOtherProbe()
{
    RawPathChooser chooser;
    chooser.offer(pathsOf({1, 2, 3, 4}));
    Clock::time_point now = Clock::now();
    run(chooser, now, {{1, 300}, {2, 100}, {3, 300}, {4, 300}}, milliseconds(3000));
    CHECK(chosenTunnel(chooser) == 2);
    int toChosen = 0;
    constexpr int kProbes = 10;
    for (int i = 0; i < kProbes; ++i) {
        const auto probe = chooser.probe(now);
        CHECK(probe.has_value());
        if (probe->path.outboundTunnel == 2) {
            ++toChosen;
        }
        now += RawPathChooser::kProbeInterval;
    }
    CHECK(toChosen == kProbes / 2);
}

void onlyItsOwnTimelyEchoesCount()
{
    RawPathChooser chooser;
    chooser.offer(pathsOf({1}));
    const Clock::time_point now = Clock::now();
    const auto probe = chooser.probe(now);
    CHECK(probe.has_value());
    CHECK(!chooser.echoed(probe->id + 1, now));
    CHECK(!chooser.echoed(probe->id, now + RawPathChooser::kProbeTimeout));
}

}  // namespace

int main()
{
    nothingOfferedNothingProbed();
    everyPathIsProbedBeforeAnyRepeats();
    theFastestPathIsChosen();
    aSmallGainDoesNotMoveTheCall();
    aPathThatStopsAnsweringIsLeft();
    aChosenPathThatIsGoneIsReplaced();
    aPathThatNeverAnsweredIsNeverChosen();
    theChosenPathGetsEveryOtherProbe();
    onlyItsOwnTimelyEchoesCount();
    return 0;
}
