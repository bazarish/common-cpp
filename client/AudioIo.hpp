// Bazarish project (c) 2026
#pragma once

#include "AudioCodec.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <vector>

namespace bazarish {

// Microphone abstraction: the call engine pulls one 20 ms PCM frame at a time.
// readFrame blocks until a frame is available (self-paced) and returns an empty
// vector once stopped, so the engine's capture loop needs no clock of its own.
// The real backend (Qt Multimedia) lives in the GUI; the lib ships only
// device-free backends so the pipeline is testable headless.
class AudioSource {
public:
    virtual ~AudioSource() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual std::vector<std::int16_t> readFrame() = 0;
};

// Speaker abstraction: the call engine pushes decoded 20 ms PCM frames.
class AudioSink {
public:
    virtual ~AudioSink() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void writeFrame(const std::vector<std::int16_t>& pcm) = 0;
};

// A device-free source that synthesises a sine tone, paced at one frame per
// 20 ms. Stands in for a microphone on headless builds and integration tests
// (a known signal that survives the Opus round trip).
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

// A sink that counts and (optionally) retains frames, for headless runs and
// tests. Thread-safe; the call engine writes from its receive thread.
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
