// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace bazarish {

// I2P LeaseSet type for SESSION CREATE. Bazarish publishes ENCRYPTED LeaseSet2
// for every destination (project-wide invariant) so floodfills cannot passively
// enumerate destinations or their tunnels; the shareable address is the blinded
// "b33". 5 = NETDB_STORE_TYPE_ENCRYPTED_LEASESET2.
inline constexpr int kEncryptedLeaseSetType = 5;

// Standard (non-encrypted) LeaseSet2. The b33 invariant is relaxed for exactly
// one case: a paid per-user destination operated from a client-owned OFFLINE
// key. i2pd cannot publish an encrypted LeaseSet2 for an offline-signature
// destination (the blinding needs the master signing private key, which offline
// delegation deliberately withholds from the server), so such a destination is
// published as a standard LeaseSet2 reachable by its plain b32.
// 3 = NETDB_STORE_TYPE_STANDARD_LEASESET2.
inline constexpr int kStandardLeaseSetType = 3;

// Number of parallel tunnels per direction in a destination's pool
// (i2cp.inbound.quantity / i2cp.outbound.quantity). This is throughput /
// redundancy (load balancing across tunnels for ONE key/address), orthogonal to
// the privacy hop length. The default suits an outbound client (a few one-shot
// fetches); a busy public server destination raises it toward the ceiling.
// I2P caps the per-pool quantity at 16.
inline constexpr int kDefaultTunnelQuantity = 3;
inline constexpr int kMaxTunnelQuantity = 16;

// I2P tunnel privacy profile (applied to every Bazarish session via SESSION
// CREATE). Higher = more hops / variance = more anonymity, more latency.
//   kMinimal: 1-hop in/out tunnels
//   kMiddle:  1-hop in/out + length variance 1
//   kMax:     2-hop in/out + length variance 1
enum class I2pPrivacy {
    eMinimal,
    eMiddle,
    eMax,
};

// The space-separated SAM SESSION CREATE tunnel options for a profile.
std::string i2pPrivacyOptions(I2pPrivacy privacy);

// Parses "minimal" / "middle" / "max" (for CLI flags); nullopt otherwise.
std::optional<I2pPrivacy> i2pPrivacyFromString(const std::string& text);

// The SAM SESSION CREATE tunnel-quantity options (inbound/outbound) for a
// destination. quantity is clamped to [1, kMaxTunnelQuantity].
std::string i2pTunnelQuantityOptions(int quantity);

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
// take tens of seconds - construction blocks until SESSION STATUS returns.
// Blocking I/O; the control socket must outlive the session.
class SamSession {
public:
    // Creates a STREAM session with EdDSA keys. privateKeys is the SAM
    // private destination blob to reuse (a stable I2P address across
    // restarts) or "TRANSIENT" for a fresh one. leaseSetType defaults to an
    // encrypted LeaseSet2 (the project-wide b33 invariant); pass a different
    // type only for interop tests. privacy selects the tunnel length/variance;
    // tunnelQuantity sets the per-direction tunnel count (throughput/redundancy
    // for one address - public server destinations raise it, outbound clients
    // keep the small default).
    SamSession(const std::string& host, std::uint16_t port, const std::string& sessionId,
        const std::string& privateKeys = "TRANSIENT", int leaseSetType = kEncryptedLeaseSetType,
        I2pPrivacy privacy = I2pPrivacy::eMax, int tunnelQuantity = kDefaultTunnelQuantity);
    ~SamSession();

    SamSession(const SamSession&) = delete;
    SamSession& operator=(const SamSession&) = delete;

    // Our own base64 destination (shareable; goes into the server card).
    const std::string& publicDestination() const;
    // The .b32.i2p address peers route to and connect to. For an encrypted
    // LeaseSet2 (the default, b33 invariant) this is the blinded "<b33>.b32.i2p"
    // host; for a standard LeaseSet2 (e.g. an offline-key per-user destination,
    // where b33 does not work) it is the standard "<b32>.b32.i2p" host. The raw
    // destination is never a routing address (project-wide .b32.i2p invariant).
    std::string routingAddress() const;
    // The private destination blob - persist it to keep a stable address.
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
    int leaseSetType_;
    int controlFd_;
};

// The SAM v3 datagram UDP port (separate from the control TCP port). The router
// forwards incoming datagrams to a client UDP socket and accepts outgoing
// datagrams on this port. Default for i2pd / Java I2P.
inline constexpr std::uint16_t kDefaultSamUdpPort = 7655;

// A SAM v3 RAW datagram session for real-time media (calls): low-overhead,
// connectionless UDP-like delivery over I2P. RAW carries no per-packet source
// destination (so each packet stays small, unlike repliable DATAGRAM whose
// ~516-byte source prefix would dwarf an audio frame) and no I2P-layer
// authentication - the caller must authenticate the payload itself (the call
// layer AEAD-seals every datagram with a per-call key). Building the session
// triggers tunnel construction and blocks until SESSION STATUS returns.
// Blocking control I/O; datagrams flow over a dedicated UDP socket.
class SamDatagramSession {
public:
    SamDatagramSession(const std::string& host, std::uint16_t controlPort,
        std::uint16_t samUdpPort, const std::string& sessionId,
        const std::string& privateKeys = "TRANSIENT",
        int leaseSetType = kEncryptedLeaseSetType, I2pPrivacy privacy = I2pPrivacy::eMax,
        int tunnelQuantity = kDefaultTunnelQuantity);
    ~SamDatagramSession();

    SamDatagramSession(const SamDatagramSession&) = delete;
    SamDatagramSession& operator=(const SamDatagramSession&) = delete;

    // Our own base64 destination (shareable) and its .b32.i2p routing address.
    const std::string& publicDestination() const;
    std::string routingAddress() const;
    const std::string& sessionId() const;

    // Sends one datagram to a destination (a base64 destination or a .b32.i2p
    // host). Best-effort like UDP; the router drops an oversize payload.
    void send(const std::string& destination, const void* data, std::size_t size);

    // Waits up to timeoutMs (negative = block indefinitely) for one incoming
    // datagram and returns its payload, or an empty vector on timeout. RAW
    // carries no source; authenticate the payload at a higher layer.
    std::vector<std::uint8_t> receive(int timeoutMs);

    // The local UDP socket fd, for external poll/select integration.
    int udpFd() const;

private:
    std::string host_;
    std::uint16_t samUdpPort_;
    std::string sessionId_;
    std::string publicDestination_;
    int leaseSetType_;
    int controlFd_;
    int udpFd_;
};

}  // namespace bazarish
