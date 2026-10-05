// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <vector>

typedef struct OpusEncoder OpusEncoder;
typedef struct OpusDecoder OpusDecoder;

namespace bazarish {

inline constexpr int kCallSampleRate = 48000;
inline constexpr int kCallChannels = 1;
inline constexpr int kCallFrameMs = 20;
inline constexpr int kCallSamplesPerFrame = kCallSampleRate / 1000 * kCallFrameMs;

// Opus encoder for one mono stream.
class AudioEncoder {
public:
    explicit AudioEncoder(int bitrateBps = 0);
    ~AudioEncoder();

    AudioEncoder(AudioEncoder&& other) noexcept;
    AudioEncoder& operator=(AudioEncoder&& other) noexcept;
    AudioEncoder(const AudioEncoder&) = delete;
    AudioEncoder& operator=(const AudioEncoder&) = delete;

    Bytes encode(const std::int16_t* pcm, int samples);

private:
    OpusEncoder* encoder_;
};

// Opus decoder for one mono stream.
class AudioDecoder {
public:
    AudioDecoder();
    ~AudioDecoder();

    AudioDecoder(AudioDecoder&& other) noexcept;
    AudioDecoder& operator=(AudioDecoder&& other) noexcept;
    AudioDecoder(const AudioDecoder&) = delete;
    AudioDecoder& operator=(const AudioDecoder&) = delete;

    std::vector<std::int16_t> decode(const Bytes& packet);

private:
    OpusDecoder* decoder_;
};

Bytes packOpusFrames(const std::vector<Bytes>& frames);
std::vector<Bytes> unpackOpusFrames(const Bytes& packed);

inline constexpr double kVoiceTargetRms = 0.10;
inline constexpr double kVoiceTargetPeak = 0.89;
inline constexpr double kVoiceMaxGain = 8.0;
inline constexpr double kVoiceSilenceRms = 0.001;
void normalizeVoicePcm(std::vector<std::int16_t>& pcm);

inline constexpr int kWaveformLevels = 16;
inline constexpr double kWaveformSilence = 0.01;
std::vector<std::uint8_t> voiceWaveform(const Bytes& packed, int bars);

class TimeStretch {
public:
    TimeStretch(std::vector<std::int16_t> pcm, double speed);

    std::size_t read(std::int16_t* out, std::size_t want);

private:
    bool step();

    std::vector<std::int16_t> pcm_;
    std::vector<double> shape_;
    std::vector<double> pending_;
    std::size_t ready_ = 0;
    std::size_t read_ = 0;
    std::size_t passthrough_ = 0;
    int window_ = 0;
    int hopSynthesis_ = 0;
    int hopAnalysis_ = 0;
    bool stretching_ = false;
};

}  // namespace bazarish
