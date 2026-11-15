// Bazarish project (c) 2026
#include "bazarish/GatewayChannel.hpp"

#include "TestUtil.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

using Clock = MediaPacer::Clock;
using Millis = std::chrono::duration<double, std::milli>;

// Opus frame of a call.
constexpr std::chrono::milliseconds kVoiceFrame{20};
constexpr std::size_t kTenMinutesOfFrames = 30000;
constexpr std::uint64_t kSeed = 2026;
constexpr std::uint32_t kAnyRef = 9;
constexpr std::size_t kHostChars = 56;
constexpr std::size_t kSealedVoiceOverhead = 28;
constexpr std::size_t kOpusLeast = 40;
constexpr std::size_t kOpusMost = 150;
constexpr std::size_t kSequenceBytes = 4;
constexpr unsigned kBitsPerByte = 8;
constexpr std::uint32_t kByteMask = 0xFF;

// Bins of the capture the old figures were read from.
constexpr double kBinMs = 5;
constexpr double kLagsMs[] = {20, 40, 60};
constexpr double kNoRhythm = 0.05;
constexpr double kOldRhythm = 0.9;
constexpr double kJitteredOldRhythm = 0.15;
// The capture's gap IQR, 4.9 ms, over 1.349 sigmas per IQR and sqrt(2) frames per gap.
constexpr double kCaptureJitterMs = 2.57;

constexpr Millis kLatencyP99Bound{35};
constexpr double kPercentile5 = 0.05;
constexpr double kPercentile50 = 0.50;
constexpr double kPercentile95 = 0.95;
constexpr double kPercentile99 = 0.99;

// 5 of header, 1 of content type, 16 of tag (RFC 8446).
constexpr std::size_t kTlsRecordOverhead = 22;
// A masked frame with a 16-bit length (RFC 6455).
constexpr std::size_t kWebSocketHeader = 8;
constexpr std::size_t kWireOverhead = kTlsRecordOverhead + kWebSocketHeader;
constexpr double kBytesPerKilobyte = 1000;
constexpr std::chrono::seconds kRateSecond{1};
constexpr std::chrono::seconds kRateWindow{5};
// The first iteration's pacer, as a reference that must fail the spread check.
constexpr std::chrono::microseconds kFixedGapLeast{3000};
constexpr std::chrono::microseconds kFixedGapMost{27000};
constexpr std::size_t kFixedSizeLeast = 320;
constexpr std::size_t kFixedSizeMost = 448;
constexpr double kMeanRateMost = 16;
constexpr double kWindowSpreadLeast = 1.2;

constexpr double kMostOfOneSize = 0.03;
constexpr double kLeastSizeEntropyBits = 6.5;

// The first raw-send on a socket names its host and may not fit a voice band.
constexpr std::size_t kRecordsNamingTheHost = 1;
constexpr std::size_t kOverflowExtra = 3;
constexpr std::chrono::milliseconds kRealIdle{300};
constexpr std::size_t kRealFrames = 50;
constexpr std::size_t kHugeBacklog = std::numeric_limits<std::size_t>::max() / 2;

class SeededRandom final : public shape::RandomSource {
public:
    explicit SeededRandom(const std::uint64_t seed) : engine_(seed) {}
    std::uint64_t next() override { return engine_(); }

private:
    std::mt19937_64 engine_;
};

class ScriptedRandom final : public shape::RandomSource {
public:
    explicit ScriptedRandom(const std::uint64_t value) : value_(value) {}
    std::uint64_t next() override { return value_; }

private:
    std::uint64_t value_;
};

class Captured final : public http::Socket {
public:
    void send(std::vector<unsigned char> message) override
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        sent_.push_back(std::move(message));
    }
    std::size_t pending() const override { return pending_.load(); }
    void close() override { open_.store(false); }
    bool open() const override { return open_.load(); }

    void backlog(const std::size_t bytes) { pending_.store(bytes); }
    std::vector<std::vector<unsigned char>> sent() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return sent_;
    }

private:
    mutable std::mutex mutex_;
    std::vector<std::vector<unsigned char>> sent_;
    std::atomic<std::size_t> pending_{0};
    std::atomic<bool> open_{true};
};

std::string anyHost()
{
    return std::string(kHostChars, 'a') + ".b32.i2p";
}

Bytes voiceFrame(const std::uint32_t sequence, std::mt19937_64& sizes)
{
    std::uniform_int_distribution<std::size_t> opus(kOpusLeast, kOpusMost);
    Bytes payload(kSealedVoiceOverhead + opus(sizes), 0);
    for (std::size_t i = 0; i < kSequenceBytes; ++i) {
        payload[i] = static_cast<std::uint8_t>(
            (sequence >> (kBitsPerByte * (kSequenceBytes - 1 - i))) & kByteMask);
    }
    return encodeRawSend(kAnyRef, anyHost(), payload);
}

std::uint32_t sequenceOf(const Bytes& frame)
{
    const RawSend sent = decodeRawSend(decode(frame));
    std::uint32_t sequence = 0;
    for (std::size_t i = 0; i < kSequenceBytes; ++i) {
        sequence = (sequence << kBitsPerByte) | sent.payload[i];
    }
    return sequence;
}

double autocorrelation(const std::vector<double>& timesMs, const double lagMs)
{
    const double last = *std::max_element(timesMs.begin(), timesMs.end());
    std::vector<double> counts(static_cast<std::size_t>(last / kBinMs) + 1, 0);
    for (const double at : timesMs) {
        counts[static_cast<std::size_t>(at / kBinMs)] += 1;
    }
    double mean = 0;
    for (const double count : counts) {
        mean += count;
    }
    mean /= static_cast<double>(counts.size());
    const std::size_t lag = static_cast<std::size_t>(lagMs / kBinMs);
    double across = 0;
    double spread = 0;
    for (std::size_t i = 0; i < counts.size(); ++i) {
        spread += (counts[i] - mean) * (counts[i] - mean);
        if (i + lag < counts.size()) {
            across += (counts[i] - mean) * (counts[i + lag] - mean);
        }
    }
    return across / spread;
}

double percentile(std::vector<double> values, const double share)
{
    std::sort(values.begin(), values.end());
    return values[static_cast<std::size_t>(share * static_cast<double>(values.size() - 1))];
}

double entropyBits(const std::vector<std::size_t>& sizes, double& mostShare)
{
    std::map<std::size_t, std::size_t> counts;
    for (const std::size_t size : sizes) {
        ++counts[size];
    }
    double bits = 0;
    mostShare = 0;
    for (const auto& [size, count] : counts) {
        (void)size;
        const double share = static_cast<double>(count) / static_cast<double>(sizes.size());
        bits -= share * std::log2(share);
        mostShare = std::max(mostShare, share);
    }
    return bits;
}

double kolmogorovSmirnov(std::vector<std::size_t> one, std::vector<std::size_t> two)
{
    std::sort(one.begin(), one.end());
    std::sort(two.begin(), two.end());
    double widest = 0;
    std::size_t i = 0;
    std::size_t j = 0;
    while (i < one.size() && j < two.size()) {
        const std::size_t at = std::min(one[i], two[j]);
        while (i < one.size() && one[i] == at) {
            ++i;
        }
        while (j < two.size() && two[j] == at) {
            ++j;
        }
        widest = std::max(widest,
            std::abs(static_cast<double>(i) / static_cast<double>(one.size())
                - static_cast<double>(j) / static_cast<double>(two.size())));
    }
    return widest;
}

struct Emitted {
    double atMs = 0;
    std::size_t plaintext = 0;
};

struct Rates {
    double mean = 0;
    double p5 = 0;
    double p50 = 0;
    double p95 = 0;
    double windowSpread = 0;
};

std::vector<double> perWindow(const std::vector<Emitted>& records, const Millis window)
{
    std::vector<double> bytes(static_cast<std::size_t>(records.back().atMs / window.count()), 0);
    for (const Emitted& record : records) {
        const auto at = static_cast<std::size_t>(record.atMs / window.count());
        if (at < bytes.size()) {
            bytes[at] += static_cast<double>(record.plaintext + kAeadTagBytes + kWireOverhead);
        }
    }
    for (double& total : bytes) {
        total /= kBytesPerKilobyte * std::chrono::duration<double>(window).count();
    }
    return bytes;
}

Rates ratesOf(const std::vector<Emitted>& records)
{
    const std::vector<double> seconds = perWindow(records, kRateSecond);
    const std::vector<double> windows = perWindow(records, kRateWindow);
    Rates rates;
    for (const double rate : seconds) {
        rates.mean += rate;
    }
    rates.mean /= static_cast<double>(seconds.size());
    rates.p5 = percentile(seconds, kPercentile5);
    rates.p50 = percentile(seconds, kPercentile50);
    rates.p95 = percentile(seconds, kPercentile95);
    rates.windowSpread = percentile(windows, kPercentile95) / percentile(windows, kPercentile5);
    return rates;
}

bool inVoiceBand(const std::size_t size, const std::size_t span)
{
    for (std::size_t frames = 1; frames <= kMediaFramesPerRecord; ++frames) {
        if (size >= frames * kMediaPadPerFrame && size <= frames * kMediaPadPerFrame + span) {
            return true;
        }
    }
    return false;
}

struct Paced {
    std::vector<Emitted> records;
    std::vector<double> voiceMs;
    std::vector<double> latencyMs;
    std::vector<std::size_t> voiceSizes;
    std::vector<std::size_t> fillerSizes;
    std::size_t fillersLikeVoice = 0;
    std::size_t pairs = 0;
    bool inOrder = true;
    std::uint64_t dropped = 0;
};

// Virtual time: every slot is taken exactly when due; records are built as the socket builds them.
Paced paceThrough(const std::vector<Clock::duration>& arrivals, shape::RandomSource& random)
{
    std::mt19937_64 sizes(kSeed);
    const Clock::time_point start{};
    MediaPacer pacer(random, start);
    HostElision hosts;
    Paced paced;
    std::size_t next = 0;
    std::uint32_t expected = 0;
    while (next < arrivals.size() || pacer.queued() > 0) {
        const Clock::time_point due = pacer.due();
        while (next < arrivals.size() && start + arrivals[next] <= due) {
            CHECK(pacer.queue(voiceFrame(static_cast<std::uint32_t>(next), sizes),
                start + arrivals[next]));
            ++next;
        }
        const MediaPacer::Slot slot = pacer.take(due);
        const MediaRegime& regime = pacer.regime();
        const double atMs = Millis(due - start).count();
        if (!slot.frames.empty()) {
            std::vector<Bytes> frames;
            for (const MediaPacer::Queued& queued : slot.frames) {
                paced.latencyMs.push_back(Millis(due - queued.at).count());
                paced.inOrder = paced.inOrder && sequenceOf(queued.frame) == expected;
                ++expected;
                frames.push_back(hosts.elide(queued.frame));
            }
            paced.pairs += slot.frames.size() > 1 ? 1 : 0;
            const std::size_t size = mediaRecord(frames, kRecordActive, regime, random).size();
            paced.records.push_back({atMs, size});
            paced.voiceMs.push_back(atMs);
            paced.voiceSizes.push_back(size);
        } else if (slot.filler) {
            const std::size_t size = fillerRecord(kRecordActive, regime, random).size();
            paced.records.push_back({atMs, size});
            paced.fillerSizes.push_back(size);
            paced.fillersLikeVoice += inVoiceBand(size, regime.padSpan) ? 1 : 0;
        }
    }
    paced.dropped = pacer.dropped();
    return paced;
}

std::vector<Emitted> fixedRateReference(shape::RandomSource& random, const double untilMs)
{
    std::vector<Emitted> records;
    Clock::duration at{};
    while (Millis(at).count() < untilMs) {
        at += std::chrono::microseconds(static_cast<std::chrono::microseconds::rep>(
            static_cast<double>(kFixedGapLeast.count())
            + shape::uniformOpen(random)
                * static_cast<double>((kFixedGapMost - kFixedGapLeast).count())));
        records.push_back({Millis(at).count(),
            kFixedSizeLeast
                + static_cast<std::size_t>(shape::uniformOpen(random)
                    * static_cast<double>(kFixedSizeMost - kFixedSizeLeast))});
    }
    return records;
}

std::vector<Clock::duration> periodic()
{
    std::vector<Clock::duration> arrivals;
    for (std::size_t i = 0; i < kTenMinutesOfFrames; ++i) {
        arrivals.push_back(kVoiceFrame * static_cast<int>(i));
    }
    return arrivals;
}

// Two frames at once every 40 ms, as an audio callback of two frames hands them over.
std::vector<Clock::duration> paired()
{
    std::vector<Clock::duration> arrivals;
    for (std::size_t i = 0; i < kTenMinutesOfFrames; ++i) {
        arrivals.push_back(kVoiceFrame * static_cast<int>(i - i % 2));
    }
    return arrivals;
}

std::vector<double> timesOf(const std::vector<Emitted>& records)
{
    std::vector<double> times;
    for (const Emitted& record : records) {
        times.push_back(record.atMs);
    }
    return times;
}

void checkBounds()
{
    ScriptedRandom lowest(0);
    ScriptedRandom highest(std::numeric_limits<std::uint64_t>::max());
    const MediaRegime low = drawMediaRegime(lowest);
    CHECK(low.gapLeast == kMediaGapFloorLeast);
    CHECK(low.gapMost == kMediaGapFloorLeast + kMediaGapWidthLeast);
    CHECK(low.padSpan == kMediaPadSpanLeast);
    CHECK(low.fillerShare < kMediaFillerShareMost);
    const MediaRegime high = drawMediaRegime(highest);
    CHECK(high.gapLeast == kMediaGapFloorMost);
    CHECK(high.gapMost == kMediaGapCeiling);
    CHECK(high.padSpan == kMediaPadSpanMost);
    CHECK(high.fillerShare <= kMediaFillerShareMost);
    CHECK(drawMediaGap(high, lowest) == high.gapLeast);
    CHECK(drawMediaGap(high, highest) == high.gapMost);

    const Bytes voice
        = encode(FrameType::eRawRecv, kAnyRef, Bytes(kSealedVoiceOverhead + kOpusMost, 0));
    CHECK(mediaRecord({voice}, 0, high, lowest).size() == kMediaPadPerFrame);
    CHECK(mediaRecord({voice}, 0, high, highest).size() == kMediaPadPerFrame + high.padSpan);
    CHECK(mediaRecord({voice, voice}, 0, high, lowest).size() == 2 * kMediaPadPerFrame);
    CHECK(fillerRecord(0, high, lowest).size() == kMediaPadPerFrame);
    CHECK(fillerRecord(0, high, highest).size() == kFillerMost);

    SeededRandom seeded(kSeed);
    const Bytes huge
        = encode(FrameType::eRawRecv, kAnyRef, Bytes(kMediaPadPerFrame + kMediaPadSpanMost, 0));
    const Bytes hugeRecord = mediaRecord({huge}, 0, high, seeded);
    CHECK(hugeRecord.size() >= static_cast<std::size_t>(kRecordPadFloor));
    CHECK(unpadRecord(hugeRecord)->frame == huge);
    CHECK_THROWS(mediaRecord({Bytes(kMaxFrameBytes + 1, 0)}, 0, high, lowest));
}

void checkRecordsAndHosts()
{
    SeededRandom random(kSeed);
    const MediaRegime regime = drawMediaRegime(random);
    const std::optional<RecordBody> filler
        = unpadRecord(fillerRecord(kRecordActive, regime, random));
    CHECK(filler.has_value());
    CHECK(isFiller(*filler));
    CHECK(filler->following.empty());
    CHECK((filler->flags & kRecordActive) != 0);

    const Bytes one = encode(FrameType::eRawRecv, kAnyRef, Bytes(kOpusMost, 1));
    const Bytes two = encode(FrameType::eRawRecv, kAnyRef, Bytes(kOpusLeast, 2));
    const std::optional<RecordBody> pair = unpadRecord(mediaRecord({one, two}, 0, regime, random));
    CHECK(pair.has_value() && !isFiller(*pair));
    CHECK(pair->frame == one);
    CHECK(pair->following == std::vector<Bytes>{two});
    CHECK(unpadRecord(padRecord(one, 0, random))->following.empty());

    const Bytes payload(kOpusLeast, 3);
    const Bytes full = encodeRawSend(kAnyRef, anyHost(), payload);
    const Bytes elsewhere
        = encodeRawSend(kAnyRef, std::string(kHostChars, 'b') + ".b32.i2p", payload);
    HostElision sender;
    CHECK(sender.elide(full) == full);
    const Bytes elided = sender.elide(full);
    CHECK(elided.size() + anyHost().size() == full.size());
    CHECK(sender.elide(elsewhere) == elsewhere);
    CHECK(sender.elide(one) == one);
    HostElision receiver;
    CHECK(!receiver.restore(elided).has_value());
    HostElision following;
    CHECK(following.restore(full) == full);
    CHECK(following.restore(elided) == full);
    CHECK(following.restore(elsewhere) == elsewhere);
    CHECK(following.restore(one) == one);
}

void checkOverflow()
{
    SeededRandom random(kSeed);
    std::mt19937_64 sizes(kSeed);
    const Clock::time_point start{};
    MediaPacer pacer(random, start);
    for (std::size_t i = 0; i < kMediaQueueLimit + kOverflowExtra; ++i) {
        const bool kept = pacer.queue(voiceFrame(static_cast<std::uint32_t>(i), sizes), start);
        CHECK(kept == (i < kMediaQueueLimit));
    }
    CHECK(pacer.dropped() == kOverflowExtra);
    CHECK(pacer.queued() == kMediaQueueLimit);
    std::uint32_t expected = kOverflowExtra;
    while (pacer.queued() > 0) {
        const MediaPacer::Slot slot = pacer.take(pacer.due());
        CHECK(slot.frames.size() == kMediaFramesPerRecord);
        CHECK(!slot.filler);
        for (const MediaPacer::Queued& queued : slot.frames) {
            CHECK(sequenceOf(queued.frame) == expected);
            ++expected;
        }
    }
    CHECK(pacer.take(pacer.due()).frames.empty());
}

void report(const char* const input, const Paced& paced)
{
    const Rates rates = ratesOf(paced.records);
    std::printf("%s: %zu records (%zu carry two frames, %zu fillers); KB/s mean %.2f, per second "
                "p5 %.2f p50 %.2f p95 %.2f, 5 s windows p95/p5 %.2f\n",
        input, paced.records.size(), paced.pairs, paced.fillerSizes.size(), rates.mean, rates.p5,
        rates.p50, rates.p95, rates.windowSpread);
    std::printf("%s: added latency p50 %.1f ms, p99 %.1f ms, max %.1f ms\n", input,
        percentile(paced.latencyMs, kPercentile50), percentile(paced.latencyMs, kPercentile99),
        percentile(paced.latencyMs, 1));
    for (const double lag : kLagsMs) {
        std::printf("%s: autocorrelation at %.0f ms, every record %.3f, voice records alone %.3f\n",
            input, lag, autocorrelation(timesOf(paced.records), lag),
            autocorrelation(paced.voiceMs, lag));
    }
}

void checkTenMinutes()
{
    const std::vector<Clock::duration> input = periodic();
    std::vector<double> old;
    for (const Clock::duration at : input) {
        old.push_back(Millis(at).count());
    }
    std::mt19937_64 jitterEngine(kSeed);
    std::normal_distribution<double> jitter(0, kCaptureJitterMs);
    std::vector<double> jittered;
    for (const double at : old) {
        jittered.push_back(std::max(0.0, at + kVoiceFrame.count() + jitter(jitterEngine)));
    }

    SeededRandom random(kSeed);
    const Paced paced = paceThrough(input, random);
    SeededRandom pairedRandom(kSeed + 1);
    const Paced twos = paceThrough(paired(), pairedRandom);
    report("a frame every 20 ms", paced);
    report("two frames every 40 ms", twos);

    for (const Paced* const run : {&paced, &twos}) {
        CHECK(run->inOrder);
        CHECK(run->dropped == 0);
        CHECK(run->latencyMs.size() == kTenMinutesOfFrames);
        CHECK(percentile(run->latencyMs, kPercentile99) <= kLatencyP99Bound.count());
        CHECK(percentile(run->latencyMs, 1) <= Millis(kMediaGapCeiling).count());
        const Rates rates = ratesOf(run->records);
        CHECK(rates.mean < kMeanRateMost);
        CHECK(rates.windowSpread > kWindowSpreadLeast);
        for (const double lag : kLagsMs) {
            CHECK(std::abs(autocorrelation(timesOf(run->records), lag)) < kNoRhythm);
        }
    }
    for (const double lag : kLagsMs) {
        const double before = autocorrelation(old, lag);
        const double beforeJittered = autocorrelation(jittered, lag);
        std::printf("unpaced at %.0f ms: %.3f, with the capture's jitter %.3f\n", lag, before,
            beforeJittered);
        CHECK(before > kOldRhythm);
        CHECK(beforeJittered > kJitteredOldRhythm);
        CHECK(std::abs(autocorrelation(paced.voiceMs, lag)) < kNoRhythm);
    }

    SeededRandom fixedRandom(kSeed);
    const Rates fixed = ratesOf(fixedRateReference(fixedRandom, paced.records.back().atMs));
    std::printf("fixed-rate reference: KB/s mean %.2f, per second p5 %.2f p50 %.2f p95 %.2f, "
                "5 s windows p95/p5 %.2f\n",
        fixed.mean, fixed.p5, fixed.p50, fixed.p95, fixed.windowSpread);
    CHECK(fixed.windowSpread < kWindowSpreadLeast);

    std::vector<std::size_t> all = paced.voiceSizes;
    all.insert(all.end(), paced.fillerSizes.begin(), paced.fillerSizes.end());
    double mostShare = 0;
    const double bits = entropyBits(all, mostShare);
    const double likeVoice = static_cast<double>(paced.fillersLikeVoice)
        / static_cast<double>(paced.fillerSizes.size());
    std::printf("record sizes: entropy %.2f bits, most common %.2f%%, voice against fillers KS "
                "%.3f, fillers inside a voice band %.1f%%\n",
        bits, mostShare * 100, kolmogorovSmirnov(paced.voiceSizes, paced.fillerSizes),
        likeVoice * 100);
    CHECK(bits > kLeastSizeEntropyBits);
    CHECK(mostShare < kMostOfOneSize);
    CHECK(likeVoice >= kFillerVoiceLike);
    std::size_t outsideFillers = 0;
    for (const std::size_t size : paced.voiceSizes) {
        outsideFillers += size < kFillerLeast || size > kFillerMost ? 1 : 0;
    }
    CHECK(outsideFillers <= kRecordsNamingTheHost);
}

void checkSocket()
{
    const Bytes sessionKey = randomBytes(kSessionKeyBytes);
    const Bytes salt = randomBytes(kTicketBytes);
    std::mt19937_64 sizes(kSeed);
    const std::shared_ptr<Captured> captured = std::make_shared<Captured>();
    std::vector<Bytes> sent;
    {
        ChannelSocket lane(captured, std::make_shared<Records>(sessionKey, salt, Side::eClient),
            ChannelHooks{[]() { return kRecordActive; }, {}});
        lane.carryMedia();
        std::this_thread::sleep_for(kRealIdle);
        const Bytes control = encodeCredit(kAnyRef, 1);
        lane.send(std::vector<unsigned char>(control.begin(), control.end()));
        for (std::size_t i = 0; i < kRealFrames; ++i) {
            sent.push_back(voiceFrame(static_cast<std::uint32_t>(i), sizes));
            lane.send(std::vector<unsigned char>(sent.back().begin(), sent.back().end()));
            std::this_thread::sleep_for(kVoiceFrame);
        }
        std::this_thread::sleep_for(kRealIdle);
        CHECK(lane.mediaDropped() == 0);
    }
    ChannelSocket far(std::make_shared<Captured>(),
        std::make_shared<Records>(sessionKey, salt, Side::eGateway));
    std::vector<Bytes> arrived;
    std::size_t fillers = 0;
    std::size_t controls = 0;
    std::size_t bytes = 0;
    for (const std::vector<unsigned char>& record : captured->sent()) {
        bytes += record.size();
        const std::optional<RecordBody> body = far.openRecord(Bytes(record.begin(), record.end()));
        CHECK(body.has_value());
        CHECK((body->flags & kRecordActive) != 0);
        if (isFiller(*body)) {
            ++fillers;
            continue;
        }
        if (body->frame.front() == static_cast<std::uint8_t>(FrameType::eStreamCredit)) {
            ++controls;
            continue;
        }
        arrived.push_back(body->frame);
        arrived.insert(arrived.end(), body->following.begin(), body->following.end());
    }
    std::printf("a real media socket: %zu records, %zu of them fillers, %zu bytes for %zu frames\n",
        captured->sent().size(), fillers, bytes, sent.size());
    CHECK(arrived == sent);
    CHECK(controls == 1);

    const std::shared_ptr<Captured> stuck = std::make_shared<Captured>();
    stuck->backlog(kHugeBacklog);
    {
        ChannelSocket lane(stuck, std::make_shared<Records>(sessionKey, salt, Side::eClient));
        lane.carryMedia();
        std::this_thread::sleep_for(kRealIdle);
        CHECK(stuck->sent().empty());
        const Bytes voice = voiceFrame(0, sizes);
        lane.send(std::vector<unsigned char>(voice.begin(), voice.end()));
        CHECK(testutil::waitFor([&]() { return stuck->sent().size() == 1; }));
    }
    ChannelSocket stuckFar(std::make_shared<Captured>(),
        std::make_shared<Records>(sessionKey, salt, Side::eGateway));
    const std::vector<unsigned char> only = stuck->sent().front();
    const std::optional<RecordBody> through
        = stuckFar.openRecord(Bytes(only.begin(), only.end()));
    CHECK(through.has_value() && !isFiller(*through));
}

}  // namespace

int main()
{
    checkBounds();
    checkRecordsAndHosts();
    checkOverflow();
    checkTenMinutes();
    checkSocket();
    std::printf("TestMediaPacing ok\n");
    return 0;
}
