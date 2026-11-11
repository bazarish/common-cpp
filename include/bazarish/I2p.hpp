// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace bazarish::i2p {

class GatewayRefusal : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class WrongGateway : public GatewayRefusal {
public:
    using GatewayRefusal::GatewayRefusal;
};

enum class Privacy { eMinimal, eMiddle, eMax };

std::optional<Privacy> privacyFromString(std::string_view text);

std::string_view privacyName(Privacy privacy);

struct TunnelLength {
    int hops = 0;
    int variance = 0;
};
TunnelLength tunnelLengthFor(Privacy privacy);

// Shared by every client destination so none stands out; calls excepted.
inline constexpr int kDefaultTunnelQuantity = 3;
// i2pd's DEFAULT_INBOUND_TUNNELS_QUANTITY.
inline constexpr int kServerTunnelQuantity = 5;
inline constexpr int kMaxTunnelQuantity = 16;
inline constexpr int kCallTunnelQuantity = 6;
inline constexpr std::size_t kMaxLeaseSetReaders = 100;

enum class Role { eClient, eServer };

class Keys {
public:
    static Keys generate();
    static Keys fromBlob(const Bytes& blob);

    Keys(const Keys&);
    Keys(Keys&&) noexcept;
    Keys& operator=(const Keys&);
    Keys& operator=(Keys&&) noexcept;
    ~Keys();

    Bytes blob() const;
    std::string privateBase64() const;
    std::string publicBase64() const;
    bool isOffline() const;
    std::int64_t transientExpires() const;
    bool b33OfflineKeysCover(std::int64_t fromUnix, std::int64_t untilUnix) const;

    Keys issueTransient(int days) const;

private:
    Keys();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Router;
    friend class Endpoint;
};

// Down this long before the delegation expires, while its keys still sign.
inline constexpr std::int64_t kDelegationLapseLeadSeconds = 60;

bool delegationLapsed(std::int64_t expiresUnix, std::int64_t now);

void requireUsableDelegation(const Keys& keys, std::int64_t now);

void requireDelegationEnds(const Keys& keys, std::int64_t declaredExpires);

std::string routingHost(const std::string& publicBase64, bool blinded = true);

std::string routerVersion();

std::vector<Bytes> sampleRouterInfos(std::size_t count);

Bytes packReseedSu3(const std::vector<Bytes>& routers, const std::string& signerId);

class Stream {
public:
    ~Stream();
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    void setReadTimeout(std::chrono::seconds timeout);
    std::size_t readSome(ByteBuffer buffer);
    void readExact(ByteBuffer buffer);
    void writeAll(ByteView data);
    std::size_t pendingBytes() const;
    void close();

private:
    Stream();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Endpoint;
};

enum class Traffic { eStream, eRaw };

struct Datagram {
    // Base64; empty for a raw datagram.
    std::string from;
    Bytes data;
};

struct EndpointConfig {
    std::optional<Keys> keys;
    Privacy privacy = Privacy::eMax;
    int tunnelQuantity = kDefaultTunnelQuantity;
    bool published = true;
    std::string label = {};
    std::string accountLabel = {};
    Traffic traffic = Traffic::eStream;
    bool realtime = false;
    bool bulk = false;
    // Empty when an unpublished stream destination dials several hosts.
    std::string target = {};
    // Raw X25519 public keys; empty leaves the lease set readable by anyone.
    std::vector<Bytes> leaseSetReaders = {};
    // Raw X25519 private key.
    Bytes leaseSetReaderKey = {};
    // False publishes a plain lease set, reached at the destination's own b32.
    bool blinded = true;
};

class Endpoint {
public:
    ~Endpoint();
    Endpoint(const Endpoint&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;

    bool ready() const;
    bool waitReady(std::chrono::seconds timeout);
    bool lost() const;

    std::string publicBase64() const;
    std::string routingHost() const;

    void refreshOfflineSignature(const Keys& newTransient);
    void setLeaseSetReaderKey(const Bytes& rawPrivate);

    std::unique_ptr<Stream> connect(const std::string& host, std::chrono::seconds timeout);
    std::unique_ptr<Stream> accept(std::string& peerBase64, std::chrono::seconds timeout);

    // host is ".b32.i2p" or base64.
    void sendDatagram(const std::string& host, ByteView data);
    Datagram receiveDatagram(std::chrono::milliseconds timeout);

    void sendRawDatagram(const std::string& host, ByteView data);
    std::vector<std::uint8_t> receiveRawDatagram(std::chrono::milliseconds timeout);

    void stop();

private:
    Endpoint();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Router;
};

enum class Backend { eEmbedded, eSam, eGateway };

struct ReseedState {
    std::string urls;
    std::string file;
};

inline constexpr std::string_view kReseedScheme = "https://";

inline bool isReseedUrl(const std::string_view url)
{
    return url.starts_with(kReseedScheme);
}

struct Capabilities {
    bool routerCounters = false;
    bool destinationCounters = false;
    bool netDbSample = false;
    bool proxy = false;
    bool offlineKeys = false;
    bool reseed = false;
    bool warmPool = false;
    // Endpoint::setLeaseSetReaderKey is supported.
    bool lateReaderKey = false;
};

inline constexpr int kDefaultSamControlPort = 7656;

struct RouterConfig {
    std::filesystem::path dataDir;
    Role role = Role::eClient;
    std::vector<std::string> reseedUrls{};
    std::filesystem::path reseedFile{};
    std::string socksProxyHost{};
    int socksProxyPort = 0;
    Backend backend = Backend::eEmbedded;
    std::string samHost = "127.0.0.1";
    int samControlPort = kDefaultSamControlPort;
    std::string gatewayHost;
    int gatewayPort = 0;
    std::string gatewayPath;
    std::string gatewayFingerprint;
    bool gatewayTls = true;
    std::chrono::milliseconds gatewayDecoyMin{0};
    std::chrono::milliseconds gatewayDecoyMax{0};
    std::chrono::seconds gatewayControlMinLife{0};
    std::chrono::seconds gatewayControlMaxLife{0};
    std::chrono::seconds gatewayControlMaxGap{0};
};

struct GatewayTarget {
    std::string host;
    int port = 0;
    std::string path;
    std::string fingerprint;
    bool tls = true;
};

struct ProxyState {
    std::string ntcp2;
    std::string ssu2;
    std::string reseed;
    bool ssu2Enabled = true;
};

struct LocalDestination {
    std::string label;
    std::string accountLabel;
    std::string host;
    bool published = false;
    bool ready = false;
    bool closing = false;
    int inboundTunnels = 0;
    int outboundTunnels = 0;
    int remoteLeaseSets = 0;
    bool localRoute = false;
};

struct TransportPeer {
    std::string ident;
    std::string transport;
    std::string endpoint;
    bool outbound = false;
};

void setI2pLogging(bool enabled);
bool i2pLogging();

// Grows when the link returns or the device moves network.
std::uint64_t carryReturns();
void networkChanged();
// Called on whichever thread grows carryReturns(); an empty function unsubscribes.
void onCarryReturned(std::function<void()> listener);

class Router {
public:
    explicit Router(RouterConfig config);
    ~Router();
    Router(const Router&) = delete;
    Router& operator=(const Router&) = delete;

    void start();
    void stop();
    bool running() const;

    bool ready() const;
    bool waitReady(std::chrono::seconds timeout);

    int knownRouters() const;
    int floodfills() const;
    int transitTunnels() const;
    int inboundTunnels() const;
    int outboundTunnels() const;
    std::vector<TransportPeer> transportPeers() const;
    std::vector<LocalDestination> localDestinations() const;

    void setSocksProxy(const std::string& host, int port);
    void setReseedUrls(const std::vector<std::string>& urls);
    ReseedState reseedState() const;
    ProxyState proxyState() const;
    // Drops the session with the current gateway: every endpoint is lost, as when it restarts.
    void repointGateway(const GatewayTarget& target);

    Capabilities capabilities() const;

    std::shared_ptr<Endpoint> createEndpoint(const EndpointConfig& config);
    void retagEndpoint(const Endpoint& endpoint, std::string label, std::string accountLabel);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::i2p
