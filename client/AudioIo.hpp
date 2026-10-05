// Bazarish project (c) 2026
#pragma once

#include "AudioCodec.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <vector>

namespace bazarish {

// Microphone abstraction: the call engine pulls one 20 ms PCM frame at a time.
class AudioSource {
public:
    virtual ~AudioSource() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual std::vector<std::int16_t> readFrame() = 0;
};

class AudioSink {
public:
    virtual ~AudioSink() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void writeFrame(const std::vector<std::int16_t>& pcm) = 0;
};

class SineAudioSource : public AudioSource {
public:
    explicit SineAudioSource(double frequencyHz = 440.0);
    void start() override;
    void stop() override;
    std::vector<std::int16_t> readFrame() override;

private:
    double frequencyHz_;
    double phase_;
    std::atomic<bool> running_;
};

class CapturingAudioSink : public AudioSink {
public:
    explicit CapturingAudioSink(bool retain = false);
    void start() override;
    void stop() override;
    void writeFrame(const std::vector<std::int16_t>& pcm) override;

    std::uint64_t frameCount() const;
    std::vector<std::vector<std::int16_t>> frames() const;

private:
    bool retain_;
    std::atomic<std::uint64_t> frameCount_;
    mutable std::mutex mutex_;
    std::vector<std::vector<std::int16_t>> frames_;
};

}  // namespace bazarish
