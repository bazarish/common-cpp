// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace bazarish::sam {

// i2pd's defaults.
inline constexpr const char* kDefaultHost = "127.0.0.1";
inline constexpr std::uint16_t kDefaultControlPort = 7656;
inline constexpr std::uint16_t kDatagramPortBelowControl = 1;

struct RouterAddress {
    std::string host = kDefaultHost;
    std::uint16_t controlPort = kDefaultControlPort;
    // 0 selects i2pd's default: one below the control port.
    std::uint16_t datagramPort = 0;

    std::uint16_t resolvedDatagramPort() const;
};

enum class Result {
    eOk,
    eInvalidId,
    eDuplicatedId,
    // The router still holds the destination for a while after its last session closed.
    eDuplicatedDest,
    eInvalidKey,
    eCantReachPeer,
    eI2pError,
    eUnknown,
};

class Error : public std::runtime_error {
public:
    Error(Result result, const std::string& message);
    Result result() const;

private:
    Result result_;
};

enum class Style { eStream, eDatagram, eRaw };

struct SessionConfig {
    std::string privateKeys;
    Style style = Style::eStream;
    i2p::Privacy privacy = i2p::Privacy::eMax;
    int tunnelQuantity = i2p::kDefaultTunnelQuantity;
    bool published = true;
    // X25519 keys in I2P base64.
    std::vector<std::string> leaseSetReaders = {};
    std::string leaseSetReaderKey = {};
    // False publishes a plain lease set, reached at the destination's own b32.
    bool blinded = true;
};

std::string probe(const RouterAddress& router);

using Socket = std::intptr_t;

class Stream {
public:
    explicit Stream(Socket socket);
    ~Stream();

    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    void setReadTimeout(int seconds);
    std::size_t readSome(ByteBuffer buffer);
    void writeAll(ByteView data);
    std::size_t pendingBytes() const;
    void close();

private:
    Socket socket_;
    int readTimeoutSeconds_ = 0;
};

class Session {
public:
    Session(RouterAddress router, SessionConfig config, std::chrono::seconds readyTimeout);
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // By value: a rebuilt session replaces them under its lock.
    std::string publicDestination() const;
    std::string privateKeys() const;
    std::string routingHost() const;

    bool alive() const;

    std::unique_ptr<Stream> connect(
        const std::string& destination, std::chrono::seconds timeout);

    void listen();
    std::unique_ptr<Stream> accept(
        std::string& peerDestination, std::chrono::milliseconds timeout);

    void sendDatagram(const std::string& destination, ByteView data);
    i2p::Datagram receiveDatagram(std::chrono::milliseconds timeout);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::sam
