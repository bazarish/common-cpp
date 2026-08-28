// Bazarish project (c) 2026
#pragma once

#include "AudioIo.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include <atomic>
#include <functional>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace bazarish {

// Per-call media datagram transport to one fixed peer. Abstract so the engine
// runs over an in-memory loopback in tests and over I2P in production.
class CallTransport {
public:
    virtual ~CallTransport() = default;
    virtual void sendDatagram(const void* data, std::size_t size) = 0;
    // Returns one datagram payload, or empty on timeout (timeoutMs, negative
    // blocks). The receive loop polls so it can observe a stop request.
    virtual std::vector<std::uint8_t> receiveDatagram(int timeoutMs) = 0;
};

// Routes media over a bazarish::i2p RAW datagram endpoint to one fixed peer
// destination (a base64 destination or a .b32.i2p host). RAW carries no
// per-packet source or I2P-layer auth; the engine AEAD-seals every datagram.
class I2pCallTransport : public CallTransport {
public:
    I2pCallTransport(bazarish::i2p::Endpoint& endpoint, std::string peerDestination);
    void sendDatagram(const void* data, std::size_t size) override;
    std::vector<std::uint8_t> receiveDatagram(int timeoutMs) override;

private:
    bazarish::i2p::Endpoint& endpoint_;
    std::string peerDestination_;
};

// Which side of the call this engine is. The role selects the AES-GCM nonce
// direction prefix so the two media streams never reuse a (key, nonce) pair.
enum class CallRole {
    eCaller,
    eCallee,
};

// Real-time media engine for a single call. Two worker threads: audio capture
// (microphone -> Opus -> seal -> transport) and one receive thread that
// demultiplexes incoming datagrams by track and routes them to playback.
//
// Every datagram is AES-256-GCM sealed with the per-call key. The 12-byte nonce
// is role(1) || track(1) || 0 0 || sequence(8, big-endian): role separates the
// two directions, track leaves room for a second stream, and the per-(role,track)
// monotonic sequence guarantees a (key, nonce) pair is never reused. A forged or
// replayed datagram fails to open and is dropped. An audio frame always fits in
// one datagram, so nothing is ever fragmented.
class CallMedia {
public:
    CallMedia(CallTransport& transport, std::unique_ptr<AudioSource> audioSource,
        std::unique_ptr<AudioSink> audioSink, const Bytes& mediaKey, CallRole role);
    ~CallMedia();

    CallMedia(const CallMedia&) = delete;
    CallMedia& operator=(const CallMedia&) = delete;

    void start();
    void stop();
    // While muted the audio capture loop keeps running but transmits nothing (the
    // peer hears concealment silence).
    void setMuted(bool muted);

    std::uint64_t packetsSent() const;
    std::uint64_t packetsReceived() const;
    // Called once, from the receive loop, when media is flowing BOTH ways: this
    // side has heard the peer, and a packet has arrived saying the peer has heard
    // this side. Each end of a call starts sending at a different moment - the
    // caller only learns where to send when the accept reaches it, and the
    // callee's destination has to publish first - so "I heard something" happens
    // seconds apart on the two ends. "We have heard each other" happens within
    // one one-way latency of each other, which is what a shared "in call" needs.
    void setOnConnected(std::function<void()> callback);

    // Loudness of the last frame in each direction, 0..1: what the microphone is
    // picking up here, and what is arriving from the peer. A call with silence on
    // one side is otherwise indistinguishable from a call with a dead microphone.
    float inputLevel() const;
    float outputLevel() const;

private:
    void audioCaptureLoop();
    void receiveLoop();

    void sealAndSend(std::uint8_t track, std::atomic<std::uint64_t>& counter, const Bytes& payload);
    void handleAudioPacket(
        std::uint64_t sequence, const Bytes& opus, bool& havePlayed, std::uint64_t& lastPlayed);

    CallTransport& transport_;
    std::unique_ptr<AudioSource> audioSource_;
    std::unique_ptr<AudioSink> audioSink_;
    Bytes mediaKey_;
    std::uint8_t sendRole_;
    std::uint8_t recvRole_;

    std::atomic<bool> running_;
    std::atomic<bool> muted_;
    std::atomic<std::uint64_t> sendSeqAudio_;
    std::atomic<std::uint64_t> packetsSent_;
    std::atomic<std::uint64_t> packetsReceived_;
    std::function<void()> onConnected_;
    // Set once a datagram from the peer has opened here: from then on every
    // datagram this side sends says so, which is what lets the peer know the
    // path works in both directions.
    std::atomic<bool> heardPeer_;
    std::atomic<bool> reportedConnected_;
    std::atomic<float> inputLevel_;
    std::atomic<float> outputLevel_;

    std::mutex sendMutex_;

    std::thread audioCaptureThread_;
    std::thread receiveThread_;
    AudioEncoder encoder_;
    AudioDecoder decoder_;
};

}  // namespace bazarish
