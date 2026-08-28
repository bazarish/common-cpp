// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <vector>

typedef struct OpusEncoder OpusEncoder;
typedef struct OpusDecoder OpusDecoder;

namespace bazarish {

// Call audio format: 48 kHz mono, 20 ms frames. Opus operates natively at these
// rates and a 20 ms frame is the standard VoIP trade-off between latency and
// per-packet overhead. One frame is kCallSamplesPerFrame signed-16 samples.
inline constexpr int kCallSampleRate = 48000;
inline constexpr int kCallChannels = 1;
inline constexpr int kCallFrameMs = 20;
inline constexpr int kCallSamplesPerFrame = kCallSampleRate / 1000 * kCallFrameMs;  // 960

// Opus encoder for one mono stream. Move-only; owns the codec state.
class AudioEncoder {
public:
    // bitrateBps of 0 leaves the codec its own choice, which is what a call
    // wants: it adapts to the link. A recording that has to fit inside one
    // message says what it may spend instead.
    explicit AudioEncoder(int bitrateBps = 0);
    ~AudioEncoder();

    AudioEncoder(AudioEncoder&& other) noexcept;
    AudioEncoder& operator=(AudioEncoder&& other) noexcept;
    AudioEncoder(const AudioEncoder&) = delete;
    AudioEncoder& operator=(const AudioEncoder&) = delete;

    // Encodes exactly kCallSamplesPerFrame samples into an Opus packet.
    Bytes encode(const std::int16_t* pcm, int samples);

private:
    OpusEncoder* encoder_;
};

// Opus decoder for one mono stream. Move-only; owns the codec state.
class AudioDecoder {
public:
    AudioDecoder();
    ~AudioDecoder();

    AudioDecoder(AudioDecoder&& other) noexcept;
    AudioDecoder& operator=(AudioDecoder&& other) noexcept;
    AudioDecoder(const AudioDecoder&) = delete;
    AudioDecoder& operator=(const AudioDecoder&) = delete;

    // Decodes one Opus packet into kCallSamplesPerFrame samples. An empty
    // packet invokes packet-loss concealment (a dropped frame is synthesised).
    std::vector<std::int16_t> decode(const Bytes& packet);

private:
    OpusDecoder* decoder_;
};

// A voice message is a run of Opus frames, each one length-prefixed, in the same
// 48 kHz mono 20 ms format calls use. There is no container beyond that: both
// ends of this protocol are this client, and an Ogg header would be bytes spent
// telling ourselves what we already know.
Bytes packOpusFrames(const std::vector<Bytes>& frames);
std::vector<Bytes> unpackOpusFrames(const Bytes& packed);

// Levels a recording before it is encoded. Speech captured at a low input gain
// reaches the other side as a whisper, and one captured hot reaches it clipped;
// the whole recording is brought to one loudness instead. The gain takes the
// recording's RMS to kVoiceTargetRms without letting its peak past
// kVoiceTargetPeak, is capped at kVoiceMaxGain so a quiet room is not lifted
// into the message as noise, and is not applied at all to what never rose above
// kVoiceSilenceRms. In place, so it is one pass over the samples.
inline constexpr double kVoiceTargetRms = 0.10;   // about -20 dBFS
inline constexpr double kVoiceTargetPeak = 0.89;  // about -1 dBFS
inline constexpr double kVoiceMaxGain = 8.0;
inline constexpr double kVoiceSilenceRms = 0.001;
void normalizeVoicePcm(std::vector<std::int16_t>& pcm);

// How loud a voice message is over its length: one bar per slice, each in
// 0..kWaveformLevels-1, taken from the decoded audio rather than from anything
// stored alongside it. Loudness is relative to the recording's own peak, so a
// quiet recording still draws a shape - but audio that never rises above
// kWaveformSilence of full scale is silence, and draws flat. Meant to be
// computed once, when a message is stored.
inline constexpr int kWaveformLevels = 16;
inline constexpr double kWaveformSilence = 0.01;
std::vector<std::uint8_t> voiceWaveform(const Bytes& packed, int bars);

// Plays a recording faster without moving its pitch. Handing the same samples to
// a faster device would raise the voice with the speed; this cuts the audio into
// overlapping windows and lays them down closer together, choosing each next
// window where it continues the last one in phase (WSOLA), so the speech keeps
// the speaker's voice.
//
// Output is produced as it is asked for rather than all at once: the search
// costs a fraction of real time per window, but a two-minute message would
// otherwise have to be ground through before the first sound came out.
class TimeStretch {
public:
    // speed of 1.0 (or below) passes the audio through untouched.
    TimeStretch(std::vector<std::int16_t> pcm, double speed);

    // Writes up to `want` samples and returns how many there were. A count below
    // `want` means the recording has ended.
    std::size_t read(std::int16_t* out, std::size_t want);

private:
    // Lays the next window down over the pending output and picks where the one
    // after it starts. False once the input is spent.
    bool step();

    std::vector<std::int16_t> pcm_;
    std::vector<double> shape_;   // the window's fade, one value a sample
    std::vector<double> pending_; // overlap-added output not yet handed out
    std::size_t ready_ = 0;       // how much of pending_ is finished
    std::size_t read_ = 0;        // where in pcm_ the next window comes from
    std::size_t passthrough_ = 0; // read position when there is nothing to do
    int window_ = 0;
    int hopSynthesis_ = 0;
    int hopAnalysis_ = 0;
    bool stretching_ = false;
};

}  // namespace bazarish
