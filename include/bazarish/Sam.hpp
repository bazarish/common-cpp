// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace bazarish {

// A connected I2P stream taken over from a SAM connection. Owns its socket
// and provides blocking byte I/O. Move-only.
class SamStream {
public:
    explicit SamStream(int fd);
    ~SamStream();

    SamStream(SamStream&& other) noexcept;
    SamStream& operator=(SamStream&& other) noexcept;
    SamStream(const SamStream&) = delete;
    SamStream& operator=(const SamStream&) = delete;

    // Reads up to buffer.size bytes; returns the count, 0 on EOF.
    std::size_t readSome(void* buffer, std::size_t size);
    // Reads exactly size bytes; throws on short read / EOF.
    void readExact(void* buffer, std::size_t size);
    void writeAll(const void* data, std::size_t size);
    // Half-closes the write side so the peer sees EOF.
    void shutdownWrite();

    int fd() const;

private:
    int fd_;
};

// Minimal SAM v3 control client (i2pd / Java I2P routers). Covers the
// handshake and destination generation; sessions and streams come with the
// federation transport work. Blocking I/O; one connection per instance.
class SamClient {
public:
    static constexpr const char* kDefaultHost = "127.0.0.1";
    static constexpr std::uint16_t kDefaultPort = 7656;

    // Connects and performs the HELLO handshake. Throws on any failure
    // (connection refused maps to the SAM_UNAVAILABLE situation upstream).
    SamClient(const std::string& host, std::uint16_t port);
    ~SamClient();

    SamClient(const SamClient&) = delete;
    SamClient& operator=(const SamClient&) = delete;

    // Negotiated SAM protocol version.
    const std::string& version() const;

    struct Destination {
        // Base64 destination (the public part, shareable).
        std::string pub;
        // Full keypair blob (keep secret).
        std::string priv;
    };

    // DEST GENERATE with EdDSA keys (SIGNATURE_TYPE 7).
    Destination generateDestination();

private:
    // Sends one SAM command line and returns the parsed reply key-values.
    // Verifies that the reply starts with the expected two words and that
    // RESULT, if present, equals OK.
    std::map<std::string, std::string> command(
        const std::string& line, const std::string& expectedReplyPrefix);

    std::string readLine();

    int fd_;
    std::string version_;
};

// A SAM v3 STREAM session: one control connection plus on-demand data
// streams. Building the session triggers I2P tunnel construction, which can
// take tens of seconds — construction blocks until SESSION STATUS returns.
// Blocking I/O; the control socket must outlive the session.
class SamSession {
public:
    // Creates a STREAM session with EdDSA keys. privateKeys is the SAM
    // private destination blob to reuse (a stable I2P address across
    // restarts) or "TRANSIENT" for a fresh one.
    SamSession(const std::string& host, std::uint16_t port, const std::string& sessionId,
        const std::string& privateKeys = "TRANSIENT");
    ~SamSession();

    SamSession(const SamSession&) = delete;
    SamSession& operator=(const SamSession&) = delete;

    // Our own base64 destination (shareable; goes into the server card).
    const std::string& publicDestination() const;
    // The private destination blob — persist it to keep a stable address.
    const std::string& privateDestination() const;
    const std::string& sessionId() const;

    // STREAM CONNECT to a base64 destination; returns the connected stream.
    SamStream connect(const std::string& destination);
    // STREAM ACCEPT: blocks until a peer connects, fills peerDestination
    // with the caller's base64 destination, returns the data stream.
    SamStream accept(std::string& peerDestination);

private:
    std::string host_;
    std::uint16_t port_;
    std::string sessionId_;
    std::string publicDestination_;
    std::string privateDestination_;
    int controlFd_;
};

}  // namespace bazarish
