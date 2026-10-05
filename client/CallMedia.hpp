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

class CallTransport {
public:
    virtual ~CallTransport() = default;
    virtual void sendDatagram(const void* data, std::size_t size) = 0;
    virtual std::vector<std::uint8_t> receiveDatagram(int timeoutMs) = 0;
};

class I2pCallTransport : public CallTransport {
public:
    I2pCallTransport(bazarish::i2p::Endpoint& endpoint, std::string peerDestination);
    void sendDatagram(const void* data, std::size_t size) override;
    std::vector<std::uint8_t> receiveDatagram(int timeoutMs) override;

private:
    bazarish::i2p::Endpoint& endpoint_;
    std::string peerDestination_;
};

enum class CallRole {
    eCaller,
    eCallee,
};

class CallMedia {
public:
    CallMedia(CallTransport& transport, std::unique_ptr<AudioSource> audioSource,
        std::unique_ptr<AudioSink> audioSink, const Bytes& mediaKey, CallRole role);
    ~CallMedia();

    CallMedia(const CallMedia&) = delete;
    CallMedia& operator=(const CallMedia&) = delete;

    void start();
    void stop();
    void setMuted(bool muted);

    std::uint64_t packetsSent() const;
    std::uint64_t packetsReceived() const;
    void setOnConnected(std::function<void()> callback);

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
