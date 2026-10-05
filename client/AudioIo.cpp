// Bazarish project (c) 2026
#include "AudioIo.hpp"

#include <chrono>
#include <cmath>
#include <thread>

namespace bazarish {

namespace {

constexpr double kTwoPi = 6.283185307179586;
constexpr double kSineAmplitude = 8000.0;

}  // namespace

SineAudioSource::SineAudioSource(const double frequencyHz)
    : frequencyHz_(frequencyHz)
    , phase_(0.0)
    , running_(false)
{
}

void SineAudioSource::start()
{
    running_ = true;
}

void SineAudioSource::stop()
{
    running_ = false;
}

std::vector<std::int16_t> SineAudioSource::readFrame()
{
    if (!running_) {
        return {};
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(kCallFrameMs));
    if (!running_) {
        return {};
    }
    std::vector<std::int16_t> frame(kCallSamplesPerFrame);
    const double step = kTwoPi * frequencyHz_ / kCallSampleRate;
    for (int i = 0; i < kCallSamplesPerFrame; ++i) {
        frame[i] = static_cast<std::int16_t>(kSineAmplitude * std::sin(phase_));
        phase_ += step;
        if (phase_ >= kTwoPi) {
            phase_ -= kTwoPi;
        }
    }
    return frame;
}

CapturingAudioSink::CapturingAudioSink(const bool retain)
    : retain_(retain)
    , frameCount_(0)
{
}

void CapturingAudioSink::start()
{
}

void CapturingAudioSink::stop()
{
}

void CapturingAudioSink::writeFrame(const std::vector<std::int16_t>& pcm)
{
    frameCount_.fetch_add(1, std::memory_order_relaxed);
    if (retain_) {
        const std::lock_guard<std::mutex> lock(mutex_);
        frames_.push_back(pcm);
    }
}

std::uint64_t CapturingAudioSink::frameCount() const
{
    return frameCount_.load(std::memory_order_relaxed);
}

std::vector<std::vector<std::int16_t>> CapturingAudioSink::frames() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return frames_;
}

}  // namespace bazarish
