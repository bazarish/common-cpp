// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The project's I2P transport. This is the ONLY surface the rest of bazarish uses
// to reach I2P: an embedded i2pd router runs in-process (no external i2pd, no SAM
// bridge). Public types expose only std and bazarish types - no i2pd or Boost
// types leak through this header, so consumers neither compile against nor link
// i2pd/Boost directly; they link Bazarish::Common and use these classes.
namespace bazarish::i2p {

// Tunnel privacy profile applied to a destination's pool (hop length / variance).
// More hops = more anonymity, more latency. A positive variance only lengthens a
// tunnel: I2P picks length + random(0..variance) hops for each one.
//   eMinimal: 1 hop in/out, no variance
//   eMiddle:  1 or 2 hops in/out (length 1, variance 1)
//   eMax:     3 hops in/out, no variance (the I2P default depth)
enum class Privacy { eMinimal, eMiddle, eMax };

// Parses "minimal" | "middle" | "max" (for CLI flags); nullopt otherwise.
std::optional<Privacy> privacyFromString(std::string_view text);

// The same three words back, so a service can report the level it is running on
// in the spelling its config file uses.
std::string_view privacyName(Privacy privacy);

// Parallel tunnels per direction in a destination's pool (throughput /
// redundancy for one address). I2P caps the per-pool quantity at 16.
inline constexpr int kDefaultTunnelQuantity = 3;
inline constexpr int kMaxTunnelQuantity = 16;

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

// The version of the embedded upstream i2pd engine (e.g. "2.60.0"), for display.
std::string routerVersion();

// --- Private reseed ---
//
// A running router can hand a starting client a slice of its own netDb, so the
// client never contacts a public reseed host - the most blocked and most telling
// part of an I2P bootstrap. No new trust is introduced: every RouterInfo carries
// its own router's signature and is verified on load, so the worst a hostile
// server can do is choose WHICH routers you learn first. Sample large and
// randomly, and leave the built-in reseeds as the fallback.

// A random sample of serialized RouterInfos from this process's netDb. Returns
// fewer than count when the netDb holds fewer. Requires a live Router.
std::vector<Bytes> sampleRouterInfos(std::size_t count);

// Writes RouterInfos into a router data directory's netDb, to be called BEFORE
// constructing the Router that will use dataDir - the engine loads its netDb
// once, at start. Malformed entries are skipped; returns how many were written.
std::size_t seedRouterInfos(
    const std::filesystem::path& dataDir, const std::vector<Bytes>& routers);

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
    // Bytes handed to the router that have not left this device yet. A write
    // returns as soon as the data is queued, so this is what separates "sent"
    // from "still on its way" - and lets a bulk writer keep the queue bounded.
    std::size_t pendingBytes() const;
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
    // What this destination is for, in the operator's words ("server dialer",
    // "call media"). Shown in the router status view; never leaves the process.
    std::string label = {};
    // Whose destination it is, when one router serves several profiles. Empty
    // for destinations that belong to no profile (e.g. a shared warm pool).
    std::string owner = {};
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

    // Raw (non-repliable) datagrams: lowest overhead - no per-packet source
    // identity and no I2P-layer authentication (authenticate the payload
    // yourself). For real-time media (calls). Best-effort like UDP.
    void sendRawDatagram(const std::string& host, const void* data, std::size_t size);
    // Wait up to timeout for one raw datagram; returns its payload (no sender
    // identity), or an empty vector on timeout.
    std::vector<std::uint8_t> receiveRawDatagram(std::chrono::milliseconds timeout);

private:
    Endpoint();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Router;
};

// Which engine moves the traffic.
//   eEmbedded: libi2pd inside this process. Its own netDb, its own tunnels, and
//              settings this process controls - what a desktop wants.
//   eSam:      an I2P router outside this process, over SAM v3. One router then
//              serves any number of processes, which is what makes a host
//              running many accounts affordable. The router is handed the
//              private keys of every destination it operates, so it has to be
//              on this machine and its address has to be loopback.
enum class Backend { eEmbedded, eSam };

// What this transport can answer. A router outside the process keeps its own
// counsel about the network it is on, so a caller asks rather than reading
// zeros as facts.
struct Capabilities {
    // Routers known, floodfills, tunnel counts, transport peers.
    bool routerCounters = false;
    // Per-destination tunnel and leaseset counts.
    bool destinationCounters = false;
    // A slice of the netDb, which is what a private reseed is made of.
    bool netDbSample = false;
    // The clearnet SOCKS proxy: setting it, and reading back what came of it.
    bool proxy = false;
    // Minting offline keys and swapping a live transient.
    bool offlineKeys = false;
};

// The default SAM control port; the datagram port sits one below it unless the
// router was configured otherwise.
inline constexpr int kDefaultSamControlPort = 7656;

struct RouterConfig {
    // All router state nests under this directory (netDb, peerProfiles,
    // destinations, keys, logs). No system i2pd locations are touched. Convention:
    // "<app-data-dir>/i2p".
    std::filesystem::path dataDir;
    // Client (notransit) or Server (relays transit). Floodfill is never enabled.
    Role role = Role::eClient;
    // Whether the router may bootstrap from i2pd's built-in reseed hosts. A
    // server has nobody to ask, so it keeps them. A client does: it takes its
    // netDb from its own server over the clearnet facade, and reaching a public
    // reseed host would announce the bootstrap to a third party - so the client
    // turns this off unless there is no clearnet facade to ask at all.
    bool allowPublicReseed = true;
    // A SOCKS5 proxy for what this router does on the clearnet: its connections to
    // other routers and the built-in reseeds. Empty host = straight out, which is
    // the default. SSU2 is switched off while one is set - its datagrams are not
    // proxied, and unproxied is not an option here.
    std::string socksProxyHost{};
    int socksProxyPort = 0;
    // Which engine to use, and where it is when it is not this process.
    Backend backend = Backend::eEmbedded;
    std::string samHost = "127.0.0.1";
    int samControlPort = kDefaultSamControlPort;
    // 0 selects the router's own default: one below the control port.
    int samDatagramPort = 0;
};

// What the engine made of the proxy configuration, read back from it rather than
// from what was asked for - the two differ when a proxy cannot serve a transport.
struct ProxyState {
    // The options as the engine holds them ("socks://host:port", or empty).
    std::string ntcp2;
    std::string ssu2;
    std::string reseed;
    // False while a proxy is set: SSU2's datagrams are not proxied at all, and
    // running them around the proxy is the one thing this must not do.
    bool ssu2Enabled = true;
};

// One active transport-layer connection to another router - a direct TCP/UDP
// session, for diagnostics.
// A destination this router currently operates, for the status view: how many
// there are and what each one is for. A snapshot - a one-time destination is
// gone from the next call.
struct LocalDestination {
    std::string label;  // EndpointConfig::label, empty when the caller set none
    std::string owner;  // EndpointConfig::owner
    std::string host;   // the ".b32.i2p" routing host
    bool published = false;
    bool ready = false;
    // The destination has been stopped and is on its way out: its tunnel pool is
    // no longer active. Told apart from a destination still coming up, which has
    // no tunnels either and is otherwise indistinguishable.
    bool closing = false;
    // Established tunnels of this destination's own pool, per direction. The
    // engine's only per-pool accessor for the outbound set is its unlocked status
    // getter, so that half is a snapshot that can be a moment stale.
    int inboundTunnels = 0;
    int outboundTunnels = 0;
    // Remote LeaseSets this destination currently holds: who it has actually
    // looked up and can talk to, which is what tells activity from an idle
    // address with tunnels. Read from the engine's own status accessor, so it
    // may be a moment stale.
    int remoteLeaseSets = 0;
};

struct TransportPeer {
    std::string ident;      // short base64 prefix of the remote router identity
    std::string transport;  // "NTCP2" or "SSU2"
    std::string endpoint;   // remote "ip:port" (v6 bracketed), empty if unknown
    bool outbound = false;  // true when we initiated the connection
};

// Router log output. By default OFF: libi2pd's own logging is fully suppressed
// (nothing reaches bazarish::log). Turn it on for debugging. Process-global and
// safe to call at any time (before or after a router exists).
void setI2pLogging(bool enabled);
bool i2pLogging();

// The embedded I2P router. One per process (it owns the process-global i2pd
// engine); constructing a second throws. The engine is initialized once for the
// life of the object; start()/stop() bring the network up and down on it so I2P
// can be honestly toggled at runtime. i2pd's own logging is routed into the
// project log (bazarish::log).
class Router {
public:
    explicit Router(RouterConfig config);
    ~Router();
    Router(const Router&) = delete;
    Router& operator=(const Router&) = delete;

    // Bring the network (tunnels, transports, netDb) up or down on the already
    // initialized engine. Constructing the Router leaves it started; stop() tears
    // the network down without de-initializing, so start() can bring it back. A
    // second InitI2P is unsupported (it double-registers config options), which is
    // why init/terminate happen once, in the constructor/destructor. Idempotent.
    void start();
    void stop();
    bool running() const;

    // True once outbound tunnels exist and netDb is warm enough to operate.
    bool ready() const;
    bool waitReady(std::chrono::seconds timeout);

    // Diagnostics.
    int knownRouters() const;     // netDb size (routers known)
    int floodfills() const;       // floodfill routers in the netDb
    int transitTunnels() const;   // participating transit tunnels (server role)
    int inboundTunnels() const;   // our destinations' inbound tunnels
    int outboundTunnels() const;  // our destinations' outbound tunnels
    // Active direct transport connections (NTCP2 / SSU2 sessions to other
    // routers). A snapshot, safe to call from another thread.
    std::vector<TransportPeer> transportPeers() const;
    // The destinations this router operates right now, in creation order. Those
    // whose Endpoint the caller has already dropped are not reported.
    std::vector<LocalDestination> localDestinations() const;

    // Routes the clearnet side through a SOCKS5 proxy, or through nothing when the
    // host is empty. Takes effect when the router's network next starts: the
    // transports read it as they come up, so a caller that wants it now stops and
    // starts the router.
    void setSocksProxy(const std::string& host, int port);
    ProxyState proxyState() const;

    // What this transport can answer. Everything it cannot throws rather than
    // returning an empty or zero answer that reads like a fact.
    Capabilities capabilities() const;

    // A fresh destination keypair. The embedded engine mints one locally; an
    // external router mints its own, because a build without the engine has no
    // way to make one. Either way the blob is the same format, so a profile
    // moves between transports.
    Keys generateKeys();

    // Create a destination on this router.
    std::shared_ptr<Endpoint> createEndpoint(const EndpointConfig& config);
    // Re-file a destination under what it is being used for now. A pool spare is
    // built before anyone owns it; the moment a caller takes it, the status view
    // would otherwise still call it a spare belonging to nobody. Status only.
    void retagEndpoint(const Endpoint& endpoint, std::string label, std::string owner);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::i2p
