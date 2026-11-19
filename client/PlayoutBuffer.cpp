// Bazarish project (c) 2026
#include "PlayoutBuffer.hpp"

#include <algorithm>
#include <utility>

namespace bazarish {

namespace {

constexpr std::uint64_t kMedianPercent = 50;
constexpr std::uint64_t kTailPercent = 99;
constexpr std::uint64_t kWholePercent = 100;

}  // namespace

PlayoutBuffer::PlayoutBuffer(
    const std::size_t targetFrames, const std::size_t limitFrames, const std::uint64_t concealLimit)
    : targetFrames_(targetFrames)
    , limitFrames_(std::max(limitFrames, targetFrames))
    , concealLimit_(concealLimit)
{
}

void PlayoutBuffer::put(const std::uint64_t sequence, Bytes opus)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (havePlayed_ && sequence <= lastPlayed_) {
        ++counts_.late;
        return;
    }
    frames_.insert_or_assign(sequence, std::move(opus));
    while (frames_.size() > limitFrames_) {
        lastPlayed_ = frames_.begin()->first;
        havePlayed_ = true;
        frames_.erase(frames_.begin());
        ++counts_.dropped;
    }
}

PlayoutBuffer::Next PlayoutBuffer::take()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (filling_) {
        if (frames_.size() < targetFrames_) {
            return {};
        }
        filling_ = false;
    }
    if (frames_.empty()) {
        ++counts_.underruns;
        filling_ = true;
        return {};
    }
    const std::uint64_t first = frames_.begin()->first;
    const std::uint64_t due = havePlayed_ ? lastPlayed_ + 1 : first;
    if (first == due || first - due > concealLimit_) {
        Next next{Kind::eFrame, std::move(frames_.begin()->second)};
        frames_.erase(frames_.begin());
        lastPlayed_ = first;
        havePlayed_ = true;
        return next;
    }
    lastPlayed_ = due;
    havePlayed_ = true;
    return {Kind::eLost, {}};
}

PlayoutBuffer::Counts PlayoutBuffer::counts() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return counts_;
}

void GapHistogram::add(const std::uint64_t gapMs)
{
    ++buckets_[std::min<std::uint64_t>(gapMs, kLongestMs)];
    ++samples_;
    maxMs_ = std::max(maxMs_, gapMs);
}

GapHistogram::Summary GapHistogram::summary() const
{
    Summary out;
    out.samples = samples_;
    out.maxMs = maxMs_;
    if (samples_ == 0) {
        return out;
    }
    const auto percentile = [this](const std::uint64_t percent) {
        const std::uint64_t wanted = (samples_ * percent + kWholePercent - 1) / kWholePercent;
        std::uint64_t seen = 0;
        for (std::size_t ms = 0; ms < buckets_.size(); ++ms) {
            seen += buckets_[ms];
            if (seen >= wanted) {
                return static_cast<std::uint64_t>(ms);
            }
        }
        return static_cast<std::uint64_t>(kLongestMs);
    };
    out.medianMs = percentile(kMedianPercent);
    out.p99Ms = percentile(kTailPercent);
    return out;
}

}  // namespace bazarish
