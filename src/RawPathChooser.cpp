// Bazarish project (c) 2026
#include "bazarish/RawPathChooser.hpp"

#include <algorithm>
#include <cmath>
#include <random>

namespace bazarish::i2p {

namespace {

constexpr int kWordBits = 32;

// Echoes are matched by id across every peer of a destination.
std::uint64_t firstProbeId()
{
    std::random_device device;
    return (static_cast<std::uint64_t>(device()) << kWordBits) | device();
}

}  // namespace

RawPathChooser::RawPathChooser()
    : nextId_(firstProbeId())
{
}

void RawPathChooser::offer(const std::vector<RawPath>& paths)
{
    std::erase_if(scores_, [&paths](const auto& entry) {
        return std::find(paths.begin(), paths.end(), entry.first) == paths.end();
    });
    for (const RawPath& path : paths) {
        scores_.try_emplace(path);
    }
    if (chosen_.has_value() && !scores_.contains(chosen_.value())) {
        chosen_.reset();
        choose();
    }
}

bool RawPathChooser::probeDue(const Clock::time_point now) const
{
    return now >= nextProbe_;
}

std::optional<RawPathChooser::Probe> RawPathChooser::probe(const Clock::time_point now)
{
    expire(now);
    choose();
    nextProbe_ = now + kProbeInterval;
    if (scores_.empty()) {
        return std::nullopt;
    }
    const bool takeChosen = chosenNext_ && chosen_.has_value();
    chosenNext_ = !chosenNext_;
    RawPath target;
    if (takeChosen) {
        target = chosen_.value();
    } else {
        const auto oldest = std::min_element(scores_.begin(), scores_.end(),
            [](const auto& a, const auto& b) { return a.second.probedAt < b.second.probedAt; });
        target = oldest->first;
    }
    scores_.at(target).probedAt = now;
    const std::uint64_t id = nextId_++;
    sent_.emplace(id, Sent{target, now});
    return Probe{id, target};
}

bool RawPathChooser::echoed(const std::uint64_t id, const Clock::time_point now)
{
    expire(now);
    const auto found = sent_.find(id);
    if (found == sent_.end()) {
        return false;
    }
    measure(found->second.path,
        std::chrono::duration_cast<std::chrono::milliseconds>(now - found->second.at));
    sent_.erase(found);
    choose();
    return true;
}

std::optional<RawPath> RawPathChooser::chosen() const
{
    return chosen_;
}

std::optional<std::chrono::milliseconds> RawPathChooser::roundTrip(const RawPath& path) const
{
    const auto found = scores_.find(path);
    if (found == scores_.end() || !found->second.measured) {
        return std::nullopt;
    }
    return std::chrono::milliseconds(std::lround(found->second.roundTripMs));
}

void RawPathChooser::measure(const RawPath& path, const std::chrono::milliseconds sample)
{
    const auto found = scores_.find(path);
    if (found == scores_.end()) {
        return;
    }
    Score& score = found->second;
    const double sampleMs = static_cast<double>(sample.count());
    if (!score.measured) {
        score.roundTripMs = sampleMs;
        score.measured = true;
        return;
    }
    score.roundTripMs += (sampleMs - score.roundTripMs) / kSmoothing;
}

void RawPathChooser::expire(const Clock::time_point now)
{
    for (auto it = sent_.begin(); it != sent_.end();) {
        if (now - it->second.at < kProbeTimeout) {
            ++it;
            continue;
        }
        const auto found = scores_.find(it->second.path);
        // Only a path that has answered can be chosen: a loss alone measures nothing.
        if (found != scores_.end() && found->second.measured) {
            measure(it->second.path, kProbeTimeout);
        }
        it = sent_.erase(it);
    }
}

void RawPathChooser::choose()
{
    const auto best = std::min_element(scores_.begin(), scores_.end(),
        [](const auto& a, const auto& b) {
            if (a.second.measured != b.second.measured) {
                return a.second.measured;
            }
            return a.second.roundTripMs < b.second.roundTripMs;
        });
    if (best == scores_.end() || !best->second.measured) {
        return;
    }
    if (!chosen_.has_value()) {
        chosen_ = best->first;
        return;
    }
    const double current = scores_.at(chosen_.value()).roundTripMs;
    if (best->second.roundTripMs + static_cast<double>(kSwitchMargin.count()) < current) {
        chosen_ = best->first;
    }
}

}  // namespace bazarish::i2p
