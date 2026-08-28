// Bazarish project (c) 2026
#include "CallMedia.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/Log.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <thread>
#include <stdexcept>
#include <utility>

namespace bazarish {

namespace {

// Datagram wire format: a 12-byte AES-GCM nonce (cleartext) followed by the
// sealed payload (ciphertext || 16-byte tag). The nonce is
// role(1) || track(1) || 0 0 || sequence(8, big-endian).
constexpr std::size_t kNonceSize = kAeadNonceBytes;  // 12

// Track byte (nonce[1]): which media stream a datagram carries. Audio is the
// only one; the byte stays in the nonce so a second track can be added without
// reusing a (key, nonce) pair.
constexpr std::uint8_t kTrackAudio = 0;

// A jump larger than this many lost frames is treated as a fresh start rather
// than synthesising a long burst of concealment audio.
constexpr std::uint64_t kMaxPlcGap = 5;

// How long the receive loop waits per poll before re-checking the stop flag.
constexpr int kReceivePollMs = 200;

// Byte 2 of the nonce says "I have heard you": the sender has already opened a
// datagram from the peer. It travels in the clear but is part of the AEAD nonce,
// so a flipped bit makes the datagram fail to open rather than lie.
constexpr std::size_t kHeardFlagOffset = 2;

Bytes makeNonce(const std::uint8_t role, const std::uint8_t track, const std::uint64_t sequence,
    const bool heardPeer = false)
{
    Bytes nonce(kNonceSize, 0);
    nonce[0] = role;
    nonce[1] = track;
    nonce[kHeardFlagOffset] = heardPeer ? 1 : 0;
    for (int i = 0; i < 8; ++i) {
        nonce[kNonceSize - 1 - i] = static_cast<unsigned char>((sequence >> (8 * i)) & 0xff);
    }
    return nonce;
}

// Loudness of one frame, 0..1, as the level meters draw it.
float frameLevel(const std::vector<std::int16_t>& pcm)
{
    if (pcm.empty()) {
        return 0.0F;
    }
    constexpr double kFullScale = 32768.0;
    double square = 0.0;
    for (const std::int16_t sample : pcm) {
        const double value = static_cast<double>(sample) / kFullScale;
        square += value * value;
    }
    return static_cast<float>(std::sqrt(square / static_cast<double>(pcm.size())));
}

std::uint64_t sequenceFromNonce(const Bytes& nonce)
{
    std::uint64_t sequence = 0;
    for (int i = 0; i < 8; ++i) {
        sequence = (sequence << 8) | nonce[kNonceSize - 8 + i];
    }
    return sequence;
}

}  // namespace

I2pCallTransport::I2pCallTransport(bazarish::i2p::Endpoint& endpoint, std::string peerDestination)
    : endpoint_(endpoint)
    , peerDestination_(std::move(peerDestination))
{
}

void I2pCallTransport::sendDatagram(const void* data, const std::size_t size)
{
    endpoint_.sendRawDatagram(peerDestination_, data, size);
}

std::vector<std::uint8_t> I2pCallTransport::receiveDatagram(const int timeoutMs)
{
    // A negative timeout means block; map it to a long poll so the engine's stop
    // flag is still observed between polls.
    const auto wait = timeoutMs < 0 ? std::chrono::milliseconds(1000)
                                     : std::chrono::milliseconds(timeoutMs);
    return endpoint_.receiveRawDatagram(wait);
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
    , inputLevel_(0.0F)
    , outputLevel_(0.0F)
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
    // The devices are opened and closed here, on the thread that drives the call,
    // and never from the media threads: an audio backend may hand its work back
    // to the thread that owns it, and a media thread waiting on this one is a
    // teardown that never finishes, because stop() joins those very threads.
    audioSink_->start();
    try {
        audioSource_->start();
    } catch (const std::exception& error) {
        // A call with no usable microphone is still a call: this side can listen,
        // and the keep-alive keeps the path proven with nothing to send.
        bazarish::log::error("call microphone unavailable: {}", error.what());
    }
    audioCaptureThread_ = std::thread(&CallMedia::audioCaptureLoop, this);
    receiveThread_ = std::thread(&CallMedia::receiveLoop, this);
}

void CallMedia::stop()
{
    if (!running_.exchange(false)) {
        return;
    }
    // Unblock the capture loop's blocking readFrame; the receive loop unblocks on
    // its own poll timeout.
    audioSource_->stop();
    if (audioCaptureThread_.joinable()) {
        audioCaptureThread_.join();
    }
    if (receiveThread_.joinable()) {
        receiveThread_.join();
    }
    audioSink_->stop();
}

void CallMedia::setMuted(const bool muted)
{
    muted_ = muted;
}

std::uint64_t CallMedia::packetsSent() const
{
    return packetsSent_.load(std::memory_order_relaxed);
}

void CallMedia::setOnConnected(std::function<void()> callback)
{
    onConnected_ = std::move(callback);
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

void CallMedia::sealAndSend(
    const std::uint8_t track, std::atomic<std::uint64_t>& counter, const Bytes& payload)
{
    const std::uint64_t sequence = counter.fetch_add(1, std::memory_order_relaxed);
    const Bytes nonce = makeNonce(sendRole_, track, sequence, heardPeer_.load());
    const Bytes sealed = aeadSeal(mediaKey_, nonce, payload);

    Bytes packet;
    packet.reserve(nonce.size() + sealed.size());
    packet.insert(packet.end(), nonce.begin(), nonce.end());
    packet.insert(packet.end(), sealed.begin(), sealed.end());
    {
        // Two capture threads (and keyframe requests) share one transport.
        const std::lock_guard<std::mutex> lock(sendMutex_);
        transport_.sendDatagram(packet.data(), packet.size());
    }
    packetsSent_.fetch_add(1, std::memory_order_relaxed);
}

// How long a call may go without sending anything before a silence packet goes
// out: it keeps the path alive and, more importantly, proves to both ends that
// media flows even when nobody is speaking and even with no microphone.
constexpr int kKeepAliveMs = 500;
constexpr int kIdlePollMs = 20;

void CallMedia::audioCaptureLoop()
{
    auto lastSent = std::chrono::steady_clock::now();
    const auto keepAlive = [&]() {
        // An empty payload decodes as concealment silence on the other side. It
        // keeps the media path proven when there is nothing to say - muted, or no
        // microphone at all - which is also what tells both ends the call is up.
        sealAndSend(kTrackAudio, sendSeqAudio_, Bytes{});
        lastSent = std::chrono::steady_clock::now();
    };
    while (running_.load()) {
        const std::vector<std::int16_t> frame = audioSource_->readFrame();
        const bool haveAudio
            = frame.size() == static_cast<std::size_t>(kCallSamplesPerFrame) && !muted_.load();
        if (frame.size() == static_cast<std::size_t>(kCallSamplesPerFrame)) {
            // Measured before the mute check: a muted microphone that is picking
            // up a voice is a thing the user should be able to see.
            inputLevel_.store(frameLevel(frame));
        }
        if (haveAudio) {
            const Bytes opus = encoder_.encode(frame.data(), static_cast<int>(frame.size()));
            sealAndSend(kTrackAudio, sendSeqAudio_, opus);
            lastSent = std::chrono::steady_clock::now();
            continue;
        }
        if (std::chrono::steady_clock::now() - lastSent
            >= std::chrono::milliseconds(kKeepAliveMs)) {
            keepAlive();
        }
        if (frame.empty()) {
            // No audio backend at all: without this the loop spins on an empty
            // read and burns a core.
            std::this_thread::sleep_for(std::chrono::milliseconds(kIdlePollMs));
        }
    }
}

void CallMedia::receiveLoop()
{
    bool audioHavePlayed = false;
    std::uint64_t audioLastPlayed = 0;
    while (running_.load()) {
        const std::vector<std::uint8_t> packet = transport_.receiveDatagram(kReceivePollMs);
        if (packet.size() <= kNonceSize) {
            continue;  // timeout or a runt with no payload
        }
        const Bytes nonce(packet.begin(), packet.begin() + kNonceSize);
        if (nonce[0] != recvRole_) {
            continue;  // not from the peer's direction
        }
        const std::uint8_t track = nonce[1];
        const Bytes sealed(packet.begin() + kNonceSize, packet.end());
        const std::optional<Bytes> opened = aeadOpen(mediaKey_, nonce, sealed);
        if (!opened.has_value()) {
            continue;  // forged, corrupt or wrong-key datagram
        }
        if (track == kTrackAudio) {
            handleAudioPacket(
                sequenceFromNonce(nonce), opened.value(), audioHavePlayed, audioLastPlayed);
        }
        // From now on our own datagrams say we have heard them.
        heardPeer_.store(true);
        // ...and once one of theirs says the same, media is proven both ways.
        if (nonce[kHeardFlagOffset] != 0 && !reportedConnected_.exchange(true)
            && onConnected_) {
            onConnected_();
        }
    }
}

void CallMedia::handleAudioPacket(const std::uint64_t sequence, const Bytes& opus,
    bool& havePlayed, std::uint64_t& lastPlayed)
{
    if (havePlayed && sequence <= lastPlayed) {
        return;  // a late or duplicate frame: its slot has passed
    }
    // Nothing reaches the speaker before media is proven in both directions: what
    // arrives until then is one half of a path still being opened, and playing it
    // is the burst of broken audio heard just before the call begins.
    const bool audible = reportedConnected_.load();
    if (havePlayed && sequence > lastPlayed + 1) {
        // Conceal a bounded run of missing frames so playback keeps pace.
        const std::uint64_t missing = std::min(sequence - lastPlayed - 1, kMaxPlcGap);
        for (std::uint64_t i = 0; i < missing; ++i) {
            const std::vector<std::int16_t> concealed = decoder_.decode(Bytes{});
            if (audible) {
                audioSink_->writeFrame(concealed);
            }
        }
    }
    const std::vector<std::int16_t> decoded = decoder_.decode(opus);
    outputLevel_.store(frameLevel(decoded));
    if (audible) {
        audioSink_->writeFrame(decoded);
    }
    lastPlayed = sequence;
    havePlayed = true;
    packetsReceived_.fetch_add(1, std::memory_order_relaxed);
}


}  // namespace bazarish
