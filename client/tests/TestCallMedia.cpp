// Bazarish project (c) 2026
#include "AudioCodec.hpp"
#include "AudioIo.hpp"
#include "CallMedia.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include "TestUtil.hpp"

#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <algorithm>
#include <vector>

using namespace bazarish;

namespace {

class ThreadWatchingSource : public SineAudioSource {
public:
    ThreadWatchingSource()
        : SineAudioSource(440.0)
    {
    }

    void start() override
    {
        startedOn_ = std::this_thread::get_id();
        SineAudioSource::start();
    }

    void stop() override
    {
        stoppedOn_ = std::this_thread::get_id();
        SineAudioSource::stop();
    }

    std::thread::id startedOn() const { return startedOn_; }
    std::thread::id stoppedOn() const { return stoppedOn_; }

private:
    std::atomic<std::thread::id> startedOn_{};
    std::atomic<std::thread::id> stoppedOn_{};
};

class ThreadWatchingSink : public CapturingAudioSink {
public:
    void start() override
    {
        startedOn_ = std::this_thread::get_id();
        CapturingAudioSink::start();
    }

    void stop() override
    {
        stoppedOn_ = std::this_thread::get_id();
        CapturingAudioSink::stop();
    }

    std::thread::id startedOn() const { return startedOn_; }
    std::thread::id stoppedOn() const { return stoppedOn_; }

private:
    std::atomic<std::thread::id> startedOn_{};
    std::atomic<std::thread::id> stoppedOn_{};
};

class LoopbackChannel {
public:
    void push(const std::vector<std::uint8_t>& packet)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            queue_.push_back(packet);
        }
        cv_.notify_one();
    }

    std::vector<std::uint8_t> pop(const int timeoutMs)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                [this] { return !queue_.empty(); })) {
            return {};
        }
        std::vector<std::uint8_t> packet = std::move(queue_.front());
        queue_.pop_front();
        return packet;
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::vector<std::uint8_t>> queue_;
};

class LoopbackTransport : public CallTransport {
public:
    LoopbackTransport(LoopbackChannel& out, LoopbackChannel& in)
        : out_(out)
        , in_(in)
    {
    }

    void sendDatagram(const void* data, const std::size_t size) override
    {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        out_.push(std::vector<std::uint8_t>(bytes, bytes + size));
    }

    std::vector<std::uint8_t> receiveDatagram(const int timeoutMs) override
    {
        return in_.pop(timeoutMs);
    }

private:
    LoopbackChannel& out_;
    LoopbackChannel& in_;
};

double frameEnergy(const std::vector<std::int16_t>& pcm)
{
    double sum = 0.0;
    for (const std::int16_t sample : pcm) {
        sum += static_cast<double>(sample) * static_cast<double>(sample);
    }
    return pcm.empty() ? 0.0 : sum / static_cast<double>(pcm.size());
}

}  // namespace

namespace {

std::vector<std::int16_t> tone(const std::size_t samples, const double amplitude)
{
    std::vector<std::int16_t> pcm(samples);
    for (std::size_t i = 0; i < samples; ++i) {
        const double phase = 2.0 * 3.14159265358979323846 * 440.0
            * static_cast<double>(i) / static_cast<double>(bazarish::kCallSampleRate);
        pcm[i] = static_cast<std::int16_t>(std::lround(amplitude * 32767.0 * std::sin(phase)));
    }
    return pcm;
}

double rmsOf(const std::vector<std::int16_t>& pcm)
{
    double square = 0.0;
    for (const std::int16_t sample : pcm) {
        const double value = static_cast<double>(sample) / 32768.0;
        square += value * value;
    }
    return std::sqrt(square / static_cast<double>(pcm.size()));
}

std::int32_t peakOf(const std::vector<std::int16_t>& pcm)
{
    std::int32_t peak = 0;
    for (const std::int16_t sample : pcm) {
        peak = std::max(peak, std::abs(static_cast<std::int32_t>(sample)));
    }
    return peak;
}

void testVoiceNormalization()
{
    const std::size_t samples = static_cast<std::size_t>(bazarish::kCallSampleRate);

    std::vector<std::int16_t> quiet = tone(samples, 0.02);
    bazarish::normalizeVoicePcm(quiet);
    CHECK(rmsOf(quiet) > 0.05);
    CHECK(peakOf(quiet) <= static_cast<std::int32_t>(bazarish::kVoiceTargetPeak * 32768.0) + 1);

    std::vector<std::int16_t> loud = tone(samples, 0.99);
    const double loudBefore = rmsOf(loud);
    bazarish::normalizeVoicePcm(loud);
    CHECK(rmsOf(loud) < loudBefore);
    CHECK(peakOf(loud) <= static_cast<std::int32_t>(bazarish::kVoiceTargetPeak * 32768.0) + 1);

    std::vector<std::int16_t> silence = tone(samples, 0.0002);
    const std::vector<std::int16_t> before = silence;
    bazarish::normalizeVoicePcm(silence);
    CHECK(silence == before);

    std::vector<std::int16_t> whisper = tone(samples, 0.002);
    bazarish::normalizeVoicePcm(whisper);
    CHECK(rmsOf(whisper) <= 0.002 * bazarish::kVoiceMaxGain / std::sqrt(2.0) + 0.001);

    std::vector<std::int16_t> nothing;
    bazarish::normalizeVoicePcm(nothing);
    CHECK(nothing.empty());
}

constexpr int kWantedFrames = 5;
constexpr int kWaitMs = 10000;
constexpr int kPollMs = 10;

}  // namespace

int main()
{
    testVoiceNormalization();
    {
        SineAudioSource source(440.0);
        source.start();
        const std::vector<std::int16_t> frame = source.readFrame();
        CHECK(frame.size() == static_cast<std::size_t>(kCallSamplesPerFrame));
        CHECK(frameEnergy(frame) > 1000.0);

        AudioEncoder encoder;
        AudioDecoder decoder;
        const Bytes packet = encoder.encode(frame.data(), static_cast<int>(frame.size()));
        CHECK(!packet.empty());
        CHECK(packet.size() < frame.size() * sizeof(std::int16_t));
        const std::vector<std::int16_t> decoded = decoder.decode(packet);
        CHECK(decoded.size() == static_cast<std::size_t>(kCallSamplesPerFrame));
        CHECK(frameEnergy(decoded) > 100.0);

        const std::vector<std::int16_t> concealed = decoder.decode(Bytes{});
        CHECK(concealed.size() == static_cast<std::size_t>(kCallSamplesPerFrame));
        source.stop();
    }

    {
        constexpr int kBars = 8;
        constexpr int kFramesPerHalf = 25;
        AudioEncoder encoder;
        SineAudioSource source(440.0);
        source.start();
        const std::vector<std::int16_t> silence(kCallSamplesPerFrame, 0);
        std::vector<Bytes> frames;
        for (int i = 0; i < kFramesPerHalf; ++i) {
            frames.push_back(encoder.encode(silence.data(), kCallSamplesPerFrame));
        }
        for (int i = 0; i < kFramesPerHalf; ++i) {
            const std::vector<std::int16_t> tone = source.readFrame();
            frames.push_back(encoder.encode(tone.data(), kCallSamplesPerFrame));
        }
        source.stop();

        const std::vector<std::uint8_t> wave = voiceWaveform(packOpusFrames(frames), kBars);
        CHECK(wave.size() == static_cast<std::size_t>(kBars));
        CHECK(wave.front() < wave.back());
        CHECK(wave.back() == kWaveformLevels - 1);

        AudioEncoder quietEncoder;
        std::vector<Bytes> quiet;
        for (int i = 0; i < kFramesPerHalf; ++i) {
            quiet.push_back(quietEncoder.encode(silence.data(), kCallSamplesPerFrame));
        }
        const std::vector<std::uint8_t> flat = voiceWaveform(packOpusFrames(quiet), kBars);
        CHECK(flat.size() == static_cast<std::size_t>(kBars));
        CHECK(std::all_of(flat.begin(), flat.end(), [](std::uint8_t bar) { return bar == 0; }));
    }

    {
        constexpr double kSpeed = 2.0;
        constexpr int kToneFrames = 100;
        constexpr double kToneHz = 440.0;
        constexpr double kCrossingsPerPeriod = 2.0;
        constexpr double kPitchTolerance = 0.05;
        constexpr double kLengthTolerance = 0.05;

        SineAudioSource source(kToneHz);
        source.start();
        std::vector<std::int16_t> tone;
        for (int i = 0; i < kToneFrames; ++i) {
            const std::vector<std::int16_t> frame = source.readFrame();
            tone.insert(tone.end(), frame.begin(), frame.end());
        }
        source.stop();

        TimeStretch stretch(tone, kSpeed);
        std::vector<std::int16_t> fast;
        std::vector<std::int16_t> chunk(kCallSamplesPerFrame);
        for (std::size_t produced = stretch.read(chunk.data(), chunk.size()); produced > 0;
            produced = stretch.read(chunk.data(), chunk.size())) {
            fast.insert(fast.end(), chunk.begin(),
                chunk.begin() + static_cast<std::ptrdiff_t>(produced));
        }

        const double ratio = static_cast<double>(fast.size()) / static_cast<double>(tone.size());
        CHECK(std::abs(ratio - 1.0 / kSpeed) < kLengthTolerance);

        const auto pitchOf = [](const std::vector<std::int16_t>& pcm) {
            int crossings = 0;
            for (std::size_t i = 1; i < pcm.size(); ++i) {
                if ((pcm[i - 1] < 0) != (pcm[i] < 0)) {
                    ++crossings;
                }
            }
            return crossings * static_cast<double>(kCallSampleRate)
                / (static_cast<double>(pcm.size()) * kCrossingsPerPeriod);
        };
        const double heard = pitchOf(fast);
        CHECK(std::abs(heard - kToneHz) / kToneHz < kPitchTolerance);
    }

    {
        LoopbackChannel aToB;
        LoopbackChannel bToA;
        LoopbackTransport callerTransport(aToB, bToA);
        LoopbackTransport calleeTransport(bToA, aToB);

        const Bytes key(kAeadKeyBytes, 0x5a);
        auto callerSink = std::make_unique<CapturingAudioSink>();
        auto calleeSink = std::make_unique<CapturingAudioSink>();
        CapturingAudioSink* const callerSinkRaw = callerSink.get();
        CapturingAudioSink* const calleeSinkRaw = calleeSink.get();

        CallMedia caller(callerTransport, std::make_unique<SineAudioSource>(440.0),
            std::move(callerSink), key, CallRole::eCaller);
        CallMedia callee(calleeTransport, std::make_unique<SineAudioSource>(660.0),
            std::move(calleeSink), key, CallRole::eCallee);

        caller.start();
        callee.start();
        // Waited for rather than slept through: on a loaded machine the media
        // threads take longer to get there, and the count is what matters.
        for (int waited = 0; waited < kWaitMs; waited += kPollMs) {
            if (caller.packetsSent() >= kWantedFrames && callee.packetsSent() >= kWantedFrames
                && caller.packetsReceived() >= kWantedFrames
                && callee.packetsReceived() >= kWantedFrames
                && callerSinkRaw->frameCount() >= kWantedFrames
                && calleeSinkRaw->frameCount() >= kWantedFrames) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
        }
        caller.stop();
        callee.stop();

        CHECK(caller.packetsSent() >= kWantedFrames);
        CHECK(callee.packetsSent() >= kWantedFrames);
        CHECK(callerSinkRaw->frameCount() >= kWantedFrames);
        CHECK(calleeSinkRaw->frameCount() >= kWantedFrames);
        CHECK(caller.packetsReceived() >= kWantedFrames);
        CHECK(callee.packetsReceived() >= kWantedFrames);
    }

    {
        LoopbackChannel aToB;
        LoopbackChannel bToA;
        LoopbackTransport callerTransport(aToB, bToA);
        LoopbackTransport calleeTransport(bToA, aToB);

        const Bytes callerKey(kAeadKeyBytes, 0x11);
        const Bytes calleeKey(kAeadKeyBytes, 0x22);
        auto calleeSink = std::make_unique<CapturingAudioSink>();
        CapturingAudioSink* const calleeSinkRaw = calleeSink.get();

        CallMedia caller(callerTransport, std::make_unique<SineAudioSource>(440.0),
            std::make_unique<CapturingAudioSink>(), callerKey, CallRole::eCaller);
        CallMedia callee(calleeTransport, std::make_unique<SineAudioSource>(440.0),
            std::move(calleeSink), calleeKey, CallRole::eCallee);

        caller.start();
        callee.start();
        // Waited for, not slept through: what is asserted is that the caller
        // sent and that the callee, holding another key, heard none of it.
        for (int waited = 0; waited < kWaitMs; waited += kPollMs) {
            if (caller.packetsSent() >= kWantedFrames) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
        }
        caller.stop();
        callee.stop();

        CHECK(caller.packetsSent() >= kWantedFrames);
        CHECK(calleeSinkRaw->frameCount() == 0);
        CHECK(callee.packetsReceived() == 0);
    }

    {
        LoopbackChannel aToB;
        LoopbackChannel bToA;
        LoopbackTransport callerTransport(aToB, bToA);
        LoopbackTransport calleeTransport(bToA, aToB);

        const Bytes key(kAeadKeyBytes, 0x7c);
        auto source = std::make_unique<ThreadWatchingSource>();
        auto sink = std::make_unique<ThreadWatchingSink>();
        ThreadWatchingSource* const sourceRaw = source.get();
        ThreadWatchingSink* const sinkRaw = sink.get();

        CallMedia caller(
            callerTransport, std::move(source), std::move(sink), key, CallRole::eCaller);
        CallMedia callee(calleeTransport, std::make_unique<SineAudioSource>(660.0),
            std::make_unique<CapturingAudioSink>(), key, CallRole::eCallee);

        const std::thread::id driver = std::this_thread::get_id();
        caller.start();
        callee.start();
        CHECK(sourceRaw->startedOn() == driver);
        CHECK(sinkRaw->startedOn() == driver);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        caller.stop();
        callee.stop();
        CHECK(sourceRaw->stoppedOn() == driver);
        CHECK(sinkRaw->stoppedOn() == driver);
    }

    std::printf("TestCallMedia OK\n");
    return 0;
}
