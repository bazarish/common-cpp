// Bazarish project (c) 2026
#include "CallMedia.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/GatewayChannel.hpp>
#include <bazarish/Log.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <thread>
#include <stdexcept>
#include <utility>

namespace bazarish {

namespace {

constexpr std::size_t kNonceSize = kAeadNonceBytes;

constexpr std::uint8_t kTrackAudio = 0;

constexpr std::uint64_t kMaxPlcGap = 5;

constexpr std::chrono::milliseconds kFrame{kCallFrameMs};
// A frame crosses two paced gateway sockets, and each may hold it up to its gap ceiling.
constexpr std::chrono::milliseconds kPlayoutDelay
    = 2 * std::chrono::ceil<std::chrono::milliseconds>(gateway::kMediaGapCeiling) + kFrame;
constexpr std::size_t kPlayoutTargetFrames
    = static_cast<std::size_t>((kPlayoutDelay + kFrame - std::chrono::milliseconds(1)) / kFrame);
constexpr std::size_t kPlayoutLimitFactor = 2;

constexpr int kReceivePollMs = 200;

constexpr std::size_t kHeardFlagOffset = 2;

Bytes makeNonce(const std::uint8_t role, const std::uint8_t track, const std::uint64_t sequence,
    const bool heardPeer = false)
{
    Bytes nonce(kNonceSize, 0);
    nonce[0] = role;
    nonce[1] = track;
    nonce[kHeardFlagOffset] = heardPeer ? 1 : 0;
    putBigEndian(ByteBuffer(nonce).last(sizeof(sequence)), sequence);
    return nonce;
}

float frameLevel(const std::vector<std::int16_t>& pcm)
{
    return static_cast<float>(pcmRms(pcm));
}

std::uint64_t sequenceFromNonce(const Bytes& nonce)
{
    return getBigEndian(ByteView(nonce).last(sizeof(std::uint64_t)));
}

}  // namespace

I2pCallTransport::I2pCallTransport(bazarish::i2p::Endpoint& endpoint, std::string peerDestination)
    : endpoint_(endpoint)
    , peerDestination_(std::move(peerDestination))
{
}

void I2pCallTransport::sendDatagram(const ByteView data)
{
    endpoint_.sendRawDatagram(peerDestination_, data);
}

std::vector<std::uint8_t> I2pCallTransport::receiveDatagram(const int timeoutMs)
{
    return endpoint_.receiveRawDatagram(std::chrono::milliseconds(timeoutMs));
}

CallMedia::CallMedia(CallTransport& transport, std::unique_ptr<AudioSource> audioSource,
    std::unique_ptr<AudioSink> audioSink, const Bytes& mediaKey, const CallRole role)
    : transport_(transport)
    , audioSource_(std::move(audioSource))
    , audioSink_(std::move(audioSink))
    , mediaKey_(mediaKey)
    , sendRole_(role == CallRole::eCaller ? 1 : 2)
    , recvRole_(role == CallRole::eCaller ? 2 : 1)
    , running_(false)
    , muted_(false)
    , sendSeqAudio_(0)
    , packetsSent_(0)
    , packetsReceived_(0)
    , heardPeer_(false)
    , reportedConnected_(false)
    , connectedAtMs_(0)
    , broken_(false)
    , inputLevel_(0.0F)
    , outputLevel_(0.0F)
    , playout_(kPlayoutTargetFrames, kPlayoutLimitFactor * kPlayoutTargetFrames, kMaxPlcGap)
{
    if (mediaKey_.size() != kAeadKeyBytes) {
        throw std::invalid_argument("CallMedia: media key must be 32 bytes");
    }
}

CallMedia::~CallMedia()
{
    stop();
}

void CallMedia::start()
{
    if (running_.exchange(true)) {
        return;
    }
    audioSink_->start();
    try {
        audioSource_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("call microphone unavailable: {}", error.what());
    }
    audioCaptureThread_
        = std::thread([this]() { runGuarded("capture", [this]() { audioCaptureLoop(); }); });
    receiveThread_ = std::thread([this]() { runGuarded("receive", [this]() { receiveLoop(); }); });
    playoutThread_ = std::thread([this]() { runGuarded("playout", [this]() { playoutLoop(); }); });
}

void CallMedia::stop()
{
    running_.store(false);
    if (!audioCaptureThread_.joinable() && !receiveThread_.joinable()
        && !playoutThread_.joinable()) {
        return;
    }
    audioSource_->stop();
    if (audioCaptureThread_.joinable()) {
        audioCaptureThread_.join();
    }
    if (receiveThread_.joinable()) {
        receiveThread_.join();
    }
    if (playoutThread_.joinable()) {
        playoutThread_.join();
    }
    audioSink_->stop();
    const GapHistogram::Summary gaps = arrivalGaps_.summary();
    const PlayoutBuffer::Counts counts = playout_.counts();
    bazarish::log::info("call media: {} arrival gaps, median {} ms, p99 {} ms, longest {} ms; "
                        "playout buffer {} ms ran dry {} times, {} frames late, {} dropped",
        gaps.samples, gaps.medianMs, gaps.p99Ms, gaps.maxMs, kPlayoutTargetFrames * kCallFrameMs,
        counts.underruns, counts.late, counts.dropped);
}

void CallMedia::setMuted(const bool muted)
{
    muted_ = muted;
}

std::uint64_t CallMedia::packetsSent() const
{
    return packetsSent_.load(std::memory_order_relaxed);
}

std::int64_t CallMedia::connectedAtMs() const
{
    return connectedAtMs_.load();
}

float CallMedia::inputLevel() const
{
    return inputLevel_.load();
}

float CallMedia::outputLevel() const
{
    return outputLevel_.load();
}

std::uint64_t CallMedia::packetsReceived() const
{
    return packetsReceived_.load(std::memory_order_relaxed);
}

bool CallMedia::broken() const
{
    return broken_.load();
}

void CallMedia::runGuarded(const std::string_view loop, const std::function<void()>& body)
{
    try {
        body();
    } catch (const std::exception& error) {
        bazarish::log::warn("call media: the {} loop failed: {}", loop, error.what());
        broken_.store(true);
        running_.store(false);
    }
}

void CallMedia::sealAndSend(
    const std::uint8_t track, std::atomic<std::uint64_t>& counter, const Bytes& payload)
{
    const std::uint64_t sequence = counter.fetch_add(1, std::memory_order_relaxed);
    const Bytes nonce = makeNonce(sendRole_, track, sequence, heardPeer_.load());
    const Bytes sealed = aeadSeal(mediaKey_.bytes(), nonce, payload);

    Bytes packet;
    packet.reserve(nonce.size() + sealed.size());
    packet.insert(packet.end(), nonce.begin(), nonce.end());
    packet.insert(packet.end(), sealed.begin(), sealed.end());
    {
        const std::lock_guard<std::mutex> lock(sendMutex_);
        transport_.sendDatagram(packet);
    }
    packetsSent_.fetch_add(1, std::memory_order_relaxed);
}

constexpr int kKeepAliveMs = 500;
constexpr int kIdlePollMs = 20;

void CallMedia::audioCaptureLoop()
{
    auto lastSent = std::chrono::steady_clock::now();
    const auto keepAlive = [&]() {
        sealAndSend(kTrackAudio, sendSeqAudio_, Bytes{});
        lastSent = std::chrono::steady_clock::now();
    };
    while (running_.load()) {
        const std::vector<std::int16_t> frame = audioSource_->readFrame();
        const bool haveAudio
            = frame.size() == static_cast<std::size_t>(kCallSamplesPerFrame) && !muted_.load();
        if (frame.size() == static_cast<std::size_t>(kCallSamplesPerFrame)) {
            inputLevel_.store(frameLevel(frame));
        }
        if (haveAudio) {
            const Bytes opus = encoder_.encode(frame);
            sealAndSend(kTrackAudio, sendSeqAudio_, opus);
            lastSent = std::chrono::steady_clock::now();
            continue;
        }
        if (std::chrono::steady_clock::now() - lastSent
            >= std::chrono::milliseconds(kKeepAliveMs)) {
            keepAlive();
        }
        if (frame.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(kIdlePollMs));
        }
    }
}

void CallMedia::receiveLoop()
{
    std::optional<std::chrono::steady_clock::time_point> lastArrival;
    while (running_.load()) {
        const std::vector<std::uint8_t> packet = transport_.receiveDatagram(kReceivePollMs);
        if (packet.size() <= kNonceSize) {
            continue;
        }
        const Bytes nonce(packet.begin(), packet.begin() + kNonceSize);
        if (nonce[0] != recvRole_) {
            continue;
        }
        const std::uint8_t track = nonce[1];
        const Bytes sealed(packet.begin() + kNonceSize, packet.end());
        const std::optional<SecretBytes> opened = aeadOpen(mediaKey_.bytes(), nonce, sealed);
        if (!opened.has_value()) {
            continue;
        }
        if (track == kTrackAudio) {
            const auto now = std::chrono::steady_clock::now();
            if (lastArrival.has_value()) {
                arrivalGaps_.add(static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - *lastArrival)
                        .count()));
            }
            lastArrival = now;
            playout_.put(sequenceFromNonce(nonce), opened->bytes());
            packetsReceived_.fetch_add(1, std::memory_order_relaxed);
        }
        heardPeer_.store(true);
        if (nonce[kHeardFlagOffset] != 0 && !reportedConnected_.exchange(true)) {
            connectedAtMs_.store(nowMillis());
        }
    }
}

void CallMedia::playoutLoop()
{
    auto due = std::chrono::steady_clock::now();
    while (running_.load()) {
        due += kFrame;
        std::this_thread::sleep_until(due);
        PlayoutBuffer::Next next = playout_.take();
        if (next.kind == PlayoutBuffer::Kind::eNothing) {
            continue;
        }
        std::vector<std::int16_t> decoded;
        try {
            decoded = decoder_.decode(next.opus);
        } catch (const std::exception& error) {
            bazarish::log::debug("call media: a packet that does not decode counts as lost: {}",
                error.what());
            decoded = decoder_.decode(Bytes{});
        }
        outputLevel_.store(frameLevel(decoded));
        if (reportedConnected_.load()) {
            audioSink_->writeFrame(decoded);
        }
    }
}

}  // namespace bazarish
