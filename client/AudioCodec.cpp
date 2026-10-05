// Bazarish project (c) 2026
#include "AudioCodec.hpp"

#include <opus/opus.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace bazarish {

namespace {

constexpr int kMaxPacketBytes = 4000;

constexpr double kFullScale = 32768.0;

constexpr int kStretchWindowMs = 30;
constexpr int kStretchSearchMs = 5;
constexpr int kStretchMatchMs = 5;
constexpr double kPi = 3.14159265358979323846;

int samplesOf(const int milliseconds)
{
    return kCallSampleRate / 1000 * milliseconds;
}

}  // namespace

AudioEncoder::AudioEncoder(const int bitrateBps)
    : encoder_(nullptr)
{
    int error = 0;
    encoder_ = opus_encoder_create(kCallSampleRate, kCallChannels, OPUS_APPLICATION_VOIP, &error);
    if (encoder_ == nullptr || error != OPUS_OK) {
        throw std::runtime_error("opus encoder creation failed");
    }
    if (bitrateBps > 0 && opus_encoder_ctl(encoder_, OPUS_SET_BITRATE(bitrateBps)) != OPUS_OK) {
        opus_encoder_destroy(encoder_);
        throw std::runtime_error("opus encoder rejected the bitrate");
    }
}

AudioEncoder::~AudioEncoder()
{
    if (encoder_ != nullptr) {
        opus_encoder_destroy(encoder_);
    }
}

AudioEncoder::AudioEncoder(AudioEncoder&& other) noexcept
    : encoder_(other.encoder_)
{
    other.encoder_ = nullptr;
}

AudioEncoder& AudioEncoder::operator=(AudioEncoder&& other) noexcept
{
    if (this != &other) {
        if (encoder_ != nullptr) {
            opus_encoder_destroy(encoder_);
        }
        encoder_ = other.encoder_;
        other.encoder_ = nullptr;
    }
    return *this;
}

Bytes AudioEncoder::encode(const std::int16_t* pcm, const int samples)
{
    Bytes packet(kMaxPacketBytes);
    const opus_int32 written
        = opus_encode(encoder_, pcm, samples, packet.data(), kMaxPacketBytes);
    if (written < 0) {
        throw std::runtime_error("opus encode failed");
    }
    packet.resize(static_cast<std::size_t>(written));
    return packet;
}

AudioDecoder::AudioDecoder()
    : decoder_(nullptr)
{
    int error = 0;
    decoder_ = opus_decoder_create(kCallSampleRate, kCallChannels, &error);
    if (decoder_ == nullptr || error != OPUS_OK) {
        throw std::runtime_error("opus decoder creation failed");
    }
}

AudioDecoder::~AudioDecoder()
{
    if (decoder_ != nullptr) {
        opus_decoder_destroy(decoder_);
    }
}

AudioDecoder::AudioDecoder(AudioDecoder&& other) noexcept
    : decoder_(other.decoder_)
{
    other.decoder_ = nullptr;
}

AudioDecoder& AudioDecoder::operator=(AudioDecoder&& other) noexcept
{
    if (this != &other) {
        if (decoder_ != nullptr) {
            opus_decoder_destroy(decoder_);
        }
        decoder_ = other.decoder_;
        other.decoder_ = nullptr;
    }
    return *this;
}

std::vector<std::int16_t> AudioDecoder::decode(const Bytes& packet)
{
    std::vector<std::int16_t> pcm(kCallSamplesPerFrame);
    const unsigned char* const data = packet.empty() ? nullptr : packet.data();
    const opus_int32 dataSize = static_cast<opus_int32>(packet.size());
    const int samples = opus_decode(decoder_, data, dataSize, pcm.data(), kCallSamplesPerFrame, 0);
    if (samples < 0) {
        throw std::runtime_error("opus decode failed");
    }
    pcm.resize(static_cast<std::size_t>(samples));
    return pcm;
}

namespace {

constexpr std::size_t kFrameLengthBytes = 2;
constexpr unsigned kByteBits = 8;
constexpr std::size_t kMaxFrameBytes = 0xFFFF;

}  // namespace

Bytes packOpusFrames(const std::vector<Bytes>& frames)
{
    Bytes packed;
    for (const Bytes& frame : frames) {
        if (frame.empty() || frame.size() > kMaxFrameBytes) {
            throw std::runtime_error("an Opus frame of an impossible size");
        }
        packed.push_back(static_cast<unsigned char>(frame.size() >> kByteBits));
        packed.push_back(static_cast<unsigned char>(frame.size() & 0xFF));
        packed.insert(packed.end(), frame.begin(), frame.end());
    }
    return packed;
}

TimeStretch::TimeStretch(std::vector<std::int16_t> pcm, const double speed)
    : pcm_(std::move(pcm))
    , window_(samplesOf(kStretchWindowMs))
    , hopSynthesis_(samplesOf(kStretchWindowMs) / 2)
{
    hopAnalysis_ = static_cast<int>(std::lround(hopSynthesis_ * speed));
    stretching_ = speed > 1.0 && pcm_.size() > static_cast<std::size_t>(window_);
    if (!stretching_) {
        return;
    }
    shape_.resize(static_cast<std::size_t>(window_));
    for (int i = 0; i < window_; ++i) {
        shape_[static_cast<std::size_t>(i)]
            = 0.5 - 0.5 * std::cos(2.0 * kPi * i / static_cast<double>(window_));
    }
    pending_.assign(static_cast<std::size_t>(window_), 0.0);
}

bool TimeStretch::step()
{
    const std::size_t window = static_cast<std::size_t>(window_);
    const std::size_t match = static_cast<std::size_t>(samplesOf(kStretchMatchMs));
    if (read_ + window > pcm_.size()) {
        return false;
    }
    if (pending_.size() < window) {
        pending_.resize(window, 0.0);
    }
    for (std::size_t i = 0; i < window; ++i) {
        pending_[i] += static_cast<double>(pcm_[read_ + i]) * shape_[i];
    }
    ready_ += static_cast<std::size_t>(hopSynthesis_);

    const std::size_t natural = read_ + static_cast<std::size_t>(hopSynthesis_);
    if (natural + match > pcm_.size()) {
        read_ = pcm_.size();
        return true;
    }
    const std::ptrdiff_t ideal = static_cast<std::ptrdiff_t>(read_ + hopAnalysis_);
    const std::ptrdiff_t search = samplesOf(kStretchSearchMs);
    std::ptrdiff_t best = ideal;
    double bestScore = -std::numeric_limits<double>::infinity();
    for (std::ptrdiff_t offset = -search; offset <= search; ++offset) {
        const std::ptrdiff_t at = ideal + offset;
        if (at < 0 || static_cast<std::size_t>(at) + match > pcm_.size()) {
            continue;
        }
        double score = 0.0;
        for (std::size_t i = 0; i < match; ++i) {
            score += static_cast<double>(pcm_[static_cast<std::size_t>(at) + i])
                * static_cast<double>(pcm_[natural + i]);
        }
        if (score > bestScore) {
            bestScore = score;
            best = at;
        }
    }
    read_ = static_cast<std::size_t>(best);
    return true;
}

std::size_t TimeStretch::read(std::int16_t* const out, const std::size_t want)
{
    if (!stretching_) {
        const std::size_t left = pcm_.size() - passthrough_;
        const std::size_t take = std::min(want, left);
        std::copy(pcm_.begin() + static_cast<std::ptrdiff_t>(passthrough_),
            pcm_.begin() + static_cast<std::ptrdiff_t>(passthrough_ + take), out);
        passthrough_ += take;
        return take;
    }
    std::size_t produced = 0;
    while (produced < want) {
        if (ready_ == 0 && !step()) {
            break;
        }
        const std::size_t take = std::min(want - produced, ready_);
        for (std::size_t i = 0; i < take; ++i) {
            const double value = std::round(pending_[i]);
            out[produced + i] = static_cast<std::int16_t>(
                std::clamp(value, -kFullScale, kFullScale - 1));
        }
        pending_.erase(pending_.begin(), pending_.begin() + static_cast<std::ptrdiff_t>(take));
        ready_ -= take;
        produced += take;
    }
    return produced;
}

std::vector<std::uint8_t> voiceWaveform(const Bytes& packed, const int bars)
{
    if (bars <= 0) {
        return {};
    }
    const std::vector<Bytes> frames = unpackOpusFrames(packed);
    if (frames.empty()) {
        return {};
    }
    AudioDecoder decoder;
    std::vector<double> frameLevels;
    frameLevels.reserve(frames.size());
    for (const Bytes& frame : frames) {
        const std::vector<std::int16_t> pcm = decoder.decode(frame);
        double sum = 0.0;
        for (const std::int16_t sample : pcm) {
            const double value = static_cast<double>(sample) / kFullScale;
            sum += value * value;
        }
        frameLevels.push_back(pcm.empty() ? 0.0 : std::sqrt(sum / static_cast<double>(pcm.size())));
    }

    std::vector<double> barLevels(static_cast<std::size_t>(bars), 0.0);
    for (std::size_t i = 0; i < frameLevels.size(); ++i) {
        const std::size_t bar
            = i * static_cast<std::size_t>(bars) / frameLevels.size();
        barLevels[bar] = std::max(barLevels[bar], frameLevels[i]);
    }
    const double peak = *std::max_element(barLevels.begin(), barLevels.end());
    std::vector<std::uint8_t> out(static_cast<std::size_t>(bars), 0);
    if (peak < kWaveformSilence) {
        return out;
    }
    for (std::size_t i = 0; i < barLevels.size(); ++i) {
        const double scaled = barLevels[i] / peak * (kWaveformLevels - 1);
        out[i] = static_cast<std::uint8_t>(std::lround(scaled));
    }
    return out;
}

void normalizeVoicePcm(std::vector<std::int16_t>& pcm)
{
    if (pcm.empty()) {
        return;
    }
    double square = 0.0;
    std::int32_t peak = 0;
    for (const std::int16_t sample : pcm) {
        const double value = static_cast<double>(sample) / kFullScale;
        square += value * value;
        peak = std::max(peak, std::abs(static_cast<std::int32_t>(sample)));
    }
    const double rms = std::sqrt(square / static_cast<double>(pcm.size()));
    if (rms < kVoiceSilenceRms || peak == 0) {
        return;
    }
    const double peakScale = static_cast<double>(peak) / kFullScale;
    const double gain = std::min({kVoiceTargetRms / rms, kVoiceTargetPeak / peakScale,
        kVoiceMaxGain});
    for (std::int16_t& sample : pcm) {
        const double scaled = std::lround(static_cast<double>(sample) * gain);
        sample = static_cast<std::int16_t>(
            std::clamp(scaled, static_cast<double>(std::numeric_limits<std::int16_t>::min()),
                static_cast<double>(std::numeric_limits<std::int16_t>::max())));
    }
}

std::vector<Bytes> unpackOpusFrames(const Bytes& packed)
{
    std::vector<Bytes> frames;
    std::size_t at = 0;
    while (at + kFrameLengthBytes <= packed.size()) {
        const std::size_t length = (static_cast<std::size_t>(packed[at]) << kByteBits)
            | static_cast<std::size_t>(packed[at + 1]);
        at += kFrameLengthBytes;
        if (length == 0 || at + length > packed.size()) {
            throw std::runtime_error("voice audio ends mid-frame");
        }
        frames.emplace_back(packed.begin() + static_cast<std::ptrdiff_t>(at),
            packed.begin() + static_cast<std::ptrdiff_t>(at + length));
        at += length;
    }
    if (at != packed.size()) {
        throw std::runtime_error("voice audio has trailing bytes");
    }
    return frames;
}

}  // namespace bazarish
