// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

// The project's I2P transport. This is the ONLY surface the rest of bazarish uses
// to reach I2P: an embedded i2pd router runs in-process (no external i2pd, no SAM
// bridge). Public types expose only std and bazarish types - no i2pd or Boost
// types leak through this header, so consumers neither compile against nor link
// i2pd/Boost directly; they link Bazarish::Common and use these classes.
namespace bazarish::i2p {

// Tunnel privacy profile applied to a destination's pool (hop length / variance).
// More hops/variance = more anonymity, more latency.
//   eMinimal: 1-hop in/out, no variance
//   eMiddle:  1-hop in/out, variance 1
//   eMax:     2-hop in/out, variance 1
enum class Privacy { eMinimal, eMiddle, eMax };

// Router participation role. Client does not relay (notransit); Server relays
// transit traffic (helps the network and blends endpoint flows with relay).
// Floodfill is never enabled in either role.
enum class Role { eClient, eServer };

// How a destination publishes its LeaseSet, which fixes its shareable address.
//   eEncrypted: encrypted LeaseSet2 -> blinded "b33" address (project default;
//               floodfills cannot enumerate the destination or its tunnels).
//   eStandard:  standard LeaseSet2 -> plain "b32" address. Required for an
//               offline-key per-user destination (the server cannot blind an
//               encrypted LS2 without the withheld master signing key).
enum class LeaseSetKind { eEncrypted, eStandard };

// An I2P destination keypair (Ed25519, signing type 7). Holds secret material;
// copyable (it is just key bytes). Consolidates what used to be duplicated as the
// resolver's OfflineKeys and the client's I2pKeys.
class Keys {
public:
    // A fresh random destination.
    static Keys generate();
    // Parse a serialized i2pd private-keys blob (a ".dat"); throws if malformed.
    static Keys fromBlob(const Bytes& blob);

    Keys(const Keys&);
    Keys(Keys&&) noexcept;
    Keys& operator=(const Keys&);
    Keys& operator=(Keys&&) noexcept;
    ~Keys();

    // Serialized private-keys blob (secret). Persist to keep a stable address.
    Bytes blob() const;
    // I2P-base64 of the private keys (the destination private form).
    std::string privateBase64() const;
    // Base64 of the public destination (shareable; feeds address derivation/cards).
    std::string publicBase64() const;
    // Plain base32 of the identity, without the ".b32.i2p" suffix (stable across
    // transients issued from this key as a master).
    std::string base32() const;
    // True if this carries an offline signature (a transient, not a bare master).
    bool isOffline() const;

    // Issue a time-boxed transient delegated from THIS (master) key, valid until
    // expiresUnix (unix seconds). The transient shares this key's base32 but signs
    // with a delegated key; the master signing secret is not in the result. The
    // air-gapped offline-custody ceremony; the live server only ever holds a
    // transient.
    Keys issueTransient(std::int64_t expiresUnix) const;

private:
    Keys();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Router;
    friend class Endpoint;
};

// The shareable ".b32.i2p" host for a destination's public base64, per leaseset
// kind (b33 for encrypted, plain b32 for standard).
std::string routingHost(const std::string& publicBase64, LeaseSetKind kind);

// A connected I2P stream. Blocking byte I/O; move-only (held via unique_ptr).
class Stream {
public:
    ~Stream();
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    // Reads up to size bytes; returns the count, 0 on EOF/close.
    std::size_t readSome(void* buffer, std::size_t size);
    // Reads exactly size bytes; throws on short read / EOF.
    void readExact(void* buffer, std::size_t size);
    // Queues size bytes for delivery.
    void writeAll(const void* data, std::size_t size);
    void close();

private:
    Stream();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Endpoint;
};

// Per-destination configuration.
struct EndpointConfig {
    // The destination identity. A generated key, a loaded master, or a transient.
    Keys keys;
    // Publish kind (and thus the address form). Use eStandard for an offline-key
    // per-user destination; eEncrypted (b33) otherwise.
    LeaseSetKind leaseSet = LeaseSetKind::eEncrypted;
    // Tunnel privacy for this destination's pool.
    Privacy privacy = Privacy::eMax;
    // Parallel tunnels per direction (throughput/redundancy), clamped to [1, 16].
    int tunnelQuantity = 3;
    // Whether to publish a LeaseSet. A pure outbound client may stay unpublished;
    // a server (or any side that must be reachable for replies) publishes.
    bool published = true;
};

// One I2P destination on the router: a stable address that can accept and open
// streams and send/receive datagrams. Obtained from Router::createEndpoint.
class Endpoint {
public:
    ~Endpoint();
    Endpoint(const Endpoint&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;

    // True once the destination has a published LeaseSet and outbound tunnels.
    bool ready() const;
    bool waitReady(std::chrono::seconds timeout);

    // The shareable base64 destination (goes into a contact card).
    std::string publicBase64() const;
    // The ".b32.i2p" host peers route to (b33 if encrypted, b32 if standard).
    std::string routingHost() const;
    // The private-keys blob; persist to keep this address across restarts.
    Bytes privateBlob() const;

    // Hot-swap the offline transient with a fresh one of the same master (same
    // address). Used to rotate an offline-key serving destination before its
    // current transient expires. No-op if this endpoint is not offline-keyed.
    void refreshOfflineSignature(const Keys& newTransient);

    // Open a stream to a ".b32.i2p" host (b32 or b33) or a base64 destination.
    // Blocks until connected or timeout; returns nullptr on failure/timeout.
    std::unique_ptr<Stream> connect(const std::string& host, std::chrono::seconds timeout);
    // Wait for an incoming stream; fills peerBase64 with the caller's destination.
    // A zero timeout blocks indefinitely. Returns nullptr on timeout.
    std::unique_ptr<Stream> accept(std::string& peerBase64, std::chrono::seconds timeout);

    // Send one repliable datagram to a host (".b32.i2p" or base64). Best-effort,
    // like UDP; oversize payloads are dropped by the router.
    void sendDatagram(const std::string& host, const void* data, std::size_t size);
    // Wait up to timeout for one datagram; fills peerBase64 with the sender's
    // destination. Returns an empty vector on timeout.
    std::vector<std::uint8_t> receiveDatagram(std::string& peerBase64,
        std::chrono::milliseconds timeout);

private:
    Endpoint();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Router;
};

struct RouterConfig {
    // All router state nests under this directory (netDb, peerProfiles,
    // destinations, keys, logs). No system i2pd locations are touched. Convention:
    // "<app-data-dir>/i2p".
    std::filesystem::path dataDir;
    // Client (notransit) or Server (relays transit). Floodfill is never enabled.
    Role role = Role::eClient;
};

// The embedded I2P router. One per process (it owns the process-global i2pd
// engine); constructing a second throws. Starting it brings up tunnels and netDb;
// i2pd's own logging is routed into the project log (bazarish::log).
class Router {
public:
    explicit Router(RouterConfig config);
    ~Router();
    Router(const Router&) = delete;
    Router& operator=(const Router&) = delete;

    // True once outbound tunnels exist and netDb is warm enough to operate.
    bool ready() const;
    bool waitReady(std::chrono::seconds timeout);

    // Diagnostics.
    int knownRouters() const;    // netDb size
    int transitTunnels() const;  // participating transit tunnels (server role)

    // Create a destination on this router.
    std::shared_ptr<Endpoint> createEndpoint(const EndpointConfig& config);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::i2p
