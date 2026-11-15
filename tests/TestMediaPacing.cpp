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
constexpr Millis kPairedLatencyP99Bound{50};
constexpr double kPercentile50 = 0.50;
constexpr double kPercentile99 = 0.99;
constexpr double kMeanGapSlackMs = 0.2;

constexpr double kMostOfOneSize = 0.02;
constexpr double kLeastSizeEntropyBits = 6.5;
// Two samples of this many from one distribution part by more than this once in a million.
constexpr double kSameSizes = 0.04;

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

Bytes voiceFrame(const std::uint32_t sequence, std::mt19937_64& sizes)
{
    std::uniform_int_distribution<std::size_t> opus(kOpusLeast, kOpusMost);
    Bytes payload(kSealedVoiceOverhead + opus(sizes), 0);
    for (std::size_t i = 0; i < kSequenceBytes; ++i) {
        payload[i] = static_cast<std::uint8_t>(
            (sequence >> (kBitsPerByte * (kSequenceBytes - 1 - i))) & kByteMask);
    }
    return encodeRawSend(kAnyRef, std::string(kHostChars, 'a') + ".b32.i2p", payload);
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

struct Paced {
    std::vector<double> slotsMs;
    std::vector<double> gapsMs;
    std::vector<double> latencyMs;
    std::vector<std::size_t> mediaSizes;
    std::vector<std::size_t> fillerSizes;
    bool inOrder = true;
    std::uint64_t dropped = 0;
};

// Virtual time: every slot is taken exactly when due.
Paced paceThrough(const std::vector<Clock::duration>& arrivals, shape::RandomSource& random)
{
    std::mt19937_64 sizes(kSeed);
    const Clock::time_point start{};
    MediaPacer pacer(random, start);
    Paced paced;
    std::size_t next = 0;
    std::uint32_t expected = 0;
    Clock::time_point previous = start;
    while (next < arrivals.size() || pacer.queued() > 0) {
        const Clock::time_point due = pacer.due();
        while (next < arrivals.size() && start + arrivals[next] <= due) {
            CHECK(pacer.queue(voiceFrame(static_cast<std::uint32_t>(next), sizes),
                start + arrivals[next]));
            ++next;
        }
        const std::optional<MediaPacer::Queued> taken = pacer.take(due);
        paced.slotsMs.push_back(Millis(due - start).count());
        paced.gapsMs.push_back(Millis(due - previous).count());
        previous = due;
        if (taken.has_value()) {
            paced.latencyMs.push_back(Millis(due - taken->at).count());
            paced.inOrder = paced.inOrder && sequenceOf(taken->frame) == expected;
            ++expected;
            paced.mediaSizes.push_back(mediaRecord(taken->frame, kRecordActive, random).size());
        } else {
            paced.fillerSizes.push_back(fillerRecord(kRecordActive, random).size());
        }
    }
    paced.dropped = pacer.dropped();
    return paced;
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

std::vector<double> asMillis(const std::vector<Clock::duration>& times)
{
    std::vector<double> millis;
    for (const Clock::duration at : times) {
        millis.push_back(Millis(at).count());
    }
    return millis;
}

void checkBounds()
{
    ScriptedRandom lowest(0);
    ScriptedRandom highest(std::numeric_limits<std::uint64_t>::max());
    CHECK(drawMediaGap(lowest) == kMediaGapMin);
    CHECK(drawMediaGap(highest) == kMediaGapMax);
    CHECK(fillerRecord(0, lowest).size() == kMediaPadFloor);
    CHECK(fillerRecord(0, highest).size() == kMediaPadCeiling);
    const Bytes voice = encode(FrameType::eRawRecv, kAnyRef, Bytes(kOpusMost, 0));
    CHECK(mediaRecord(voice, 0, lowest).size() == kMediaPadFloor);
    const Bytes wide = encode(FrameType::eRawRecv, kAnyRef, Bytes(kMediaPadFloor, 0));
    CHECK(mediaRecord(wide, 0, lowest).size() == kRecordHeaderBytes + wide.size());
    SeededRandom seeded(kSeed);
    const Bytes huge = encode(FrameType::eRawRecv, kAnyRef, Bytes(kMediaPadCeiling, 0));
    const Bytes hugeRecord = mediaRecord(huge, 0, seeded);
    CHECK(hugeRecord.size() >= static_cast<std::size_t>(kRecordPadFloor));
    CHECK(unpadRecord(hugeRecord)->frame == huge);
    CHECK_THROWS(mediaRecord(Bytes(kMaxFrameBytes + 1, 0), 0, lowest));
}

void checkFillers()
{
    SeededRandom random(kSeed);
    const std::optional<RecordBody> filler = unpadRecord(fillerRecord(kRecordActive, random));
    CHECK(filler.has_value());
    CHECK(isFiller(*filler));
    CHECK(filler->frame.empty());
    CHECK((filler->flags & kRecordActive) != 0);
    const Bytes voice = encode(FrameType::eRawRecv, kAnyRef, Bytes(kOpusMost, 1));
    const std::optional<RecordBody> media = unpadRecord(mediaRecord(voice, kRecordActive, random));
    CHECK(media.has_value());
    CHECK(!isFiller(*media));
    CHECK(media->frame == voice);
    CHECK(!isFiller(*unpadRecord(padRecord(voice, kRecordActive, random))));
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
    for (std::size_t i = 0; i < kMediaQueueLimit; ++i) {
        const std::optional<MediaPacer::Queued> taken = pacer.take(pacer.due());
        CHECK(taken.has_value());
        CHECK(sequenceOf(taken->frame) == kOverflowExtra + i);
    }
    CHECK(!pacer.take(pacer.due()).has_value());
}

void checkRhythmLatencyAndSizes()
{
    SeededRandom random(kSeed);
    const std::vector<Clock::duration> input = periodic();
    const Paced paced = paceThrough(input, random);
    CHECK(paced.inOrder);
    CHECK(paced.dropped == 0);
    CHECK(paced.latencyMs.size() == kTenMinutesOfFrames);

    const std::vector<double> old = asMillis(input);
    std::mt19937_64 jitterEngine(kSeed);
    std::normal_distribution<double> jitter(0, kCaptureJitterMs);
    std::vector<double> jittered;
    for (const double at : old) {
        jittered.push_back(std::max(0.0, at + kVoiceFrame.count() + jitter(jitterEngine)));
    }
    for (const double lag : kLagsMs) {
        const double before = autocorrelation(old, lag);
        const double beforeJittered = autocorrelation(jittered, lag);
        const double after = autocorrelation(paced.slotsMs, lag);
        std::printf("autocorrelation at %.0f ms (%.0f ms bins): unpaced %.3f, unpaced with "
                    "capture jitter %.3f, paced %.3f\n",
            lag, kBinMs, before, beforeJittered, after);
        CHECK(before > kOldRhythm);
        CHECK(beforeJittered > kJitteredOldRhythm);
        CHECK(std::abs(after) < kNoRhythm);
    }

    double gapSum = 0;
    for (const double gap : paced.gapsMs) {
        CHECK(gap >= Millis(kMediaGapMin).count());
        CHECK(gap <= Millis(kMediaGapMax).count());
        gapSum += gap;
    }
    const double meanGap = gapSum / static_cast<double>(paced.gapsMs.size());
    const double expectedMean = Millis(kMediaGapMin + kMediaGapMax).count() / 2;
    std::printf("slots: %zu (%zu media, %zu fillers), mean gap %.2f ms\n", paced.slotsMs.size(),
        paced.mediaSizes.size(), paced.fillerSizes.size(), meanGap);
    CHECK(std::abs(meanGap - expectedMean) < kMeanGapSlackMs);
    CHECK(meanGap < Millis(kVoiceFrame).count());

    const double p50 = percentile(paced.latencyMs, kPercentile50);
    const double p99 = percentile(paced.latencyMs, kPercentile99);
    const double most = percentile(paced.latencyMs, 1);
    std::printf("added latency, a frame every 20 ms: p50 %.1f ms, p99 %.1f ms, max %.1f ms\n",
        p50, p99, most);
    CHECK(p99 <= kLatencyP99Bound.count());

    SeededRandom pairedRandom(kSeed);
    const Paced twos = paceThrough(paired(), pairedRandom);
    CHECK(twos.inOrder);
    CHECK(twos.dropped == 0);
    const double pairedP99 = percentile(twos.latencyMs, kPercentile99);
    std::printf("added latency, two frames every 40 ms: p50 %.1f ms, p99 %.1f ms, max %.1f ms\n",
        percentile(twos.latencyMs, kPercentile50), pairedP99, percentile(twos.latencyMs, 1));
    CHECK(pairedP99 <= kPairedLatencyP99Bound.count());

    std::vector<std::size_t> all = paced.mediaSizes;
    all.insert(all.end(), paced.fillerSizes.begin(), paced.fillerSizes.end());
    for (const std::size_t size : all) {
        CHECK(size >= kMediaPadFloor);
        CHECK(size <= kMediaPadCeiling);
    }
    double mostShare = 0;
    const double bits = entropyBits(all, mostShare);
    const double distance = kolmogorovSmirnov(paced.mediaSizes, paced.fillerSizes);
    std::printf("record sizes: entropy %.2f bits, most common size %.2f%%, media against "
                "fillers KS %.4f\n",
        bits, mostShare * 100, distance);
    CHECK(bits > kLeastSizeEntropyBits);
    CHECK(mostShare < kMostOfOneSize);
    CHECK(distance < kSameSizes);
}

std::vector<RecordBody> openAll(const std::vector<std::vector<unsigned char>>& wire, Records& far)
{
    std::vector<RecordBody> bodies;
    for (const std::vector<unsigned char>& record : wire) {
        const std::optional<Bytes> opened = far.open(Bytes(record.begin(), record.end()));
        CHECK(opened.has_value());
        const std::optional<RecordBody> body = unpadRecord(*opened);
        CHECK(body.has_value());
        bodies.push_back(*body);
    }
    return bodies;
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
        CHECK(!captured->sent().empty());
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
    Records far(sessionKey, salt, Side::eGateway);
    std::vector<Bytes> arrived;
    std::size_t fillers = 0;
    std::size_t padded = 0;
    for (const RecordBody& body : openAll(captured->sent(), far)) {
        CHECK((body.flags & kRecordActive) != 0);
        if (isFiller(body)) {
            ++fillers;
            continue;
        }
        if (body.frame.front() == static_cast<std::uint8_t>(FrameType::eStreamCredit)) {
            ++padded;
            continue;
        }
        arrived.push_back(body.frame);
    }
    std::size_t outsideMediaSizes = 0;
    for (const std::vector<unsigned char>& record : captured->sent()) {
        const std::size_t plaintext = record.size() - kAeadTagBytes;
        if (plaintext < kMediaPadFloor || plaintext > kMediaPadCeiling) {
            CHECK(plaintext >= static_cast<std::size_t>(kRecordPadFloor));
            ++outsideMediaSizes;
        }
    }
    CHECK(outsideMediaSizes == padded);
    std::printf("a real media socket: %zu records, %zu of them fillers\n", captured->sent().size(),
        fillers);
    CHECK(arrived == sent);
    CHECK(padded == 1);
    CHECK(fillers > 0);

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
    Records stuckFar(sessionKey, salt, Side::eGateway);
    const std::vector<RecordBody> through = openAll(stuck->sent(), stuckFar);
    CHECK(through.size() == 1 && !isFiller(through.front()));
}

}  // namespace

int main()
{
    checkBounds();
    checkFillers();
    checkOverflow();
    checkRhythmLatencyAndSizes();
    checkSocket();
    std::printf("TestMediaPacing ok\n");
    return 0;
}
