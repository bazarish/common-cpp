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

namespace bazarish::i2p {

enum class Privacy { eMinimal, eMiddle, eMax };

std::optional<Privacy> privacyFromString(std::string_view text);

std::string_view privacyName(Privacy privacy);

inline constexpr int kDefaultTunnelQuantity = 3;
inline constexpr int kMaxTunnelQuantity = 16;

enum class Role { eClient, eServer };

class Keys {
public:
    static Keys generate();
    // Parse a serialized i2pd private-keys blob (a ".dat"); throws if malformed.
    static Keys fromBlob(const Bytes& blob);

    Keys(const Keys&);
    Keys(Keys&&) noexcept;
    Keys& operator=(const Keys&);
    Keys& operator=(Keys&&) noexcept;
    ~Keys();

    Bytes blob() const;
    // I2P-base64 of the private keys (the destination private form).
    std::string privateBase64() const;
    // Base64 of the public destination (shareable; feeds address derivation/cards).
    std::string publicBase64() const;
    bool isOffline() const;
    std::int64_t transientExpires() const;
    int b33OfflineKeyDays() const;

    Keys issueTransient(int days) const;

private:
    Keys();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Router;
    friend class Endpoint;
};

std::string routingHost(const std::string& publicBase64);

// The version of the embedded upstream i2pd engine (e.g.
std::string routerVersion();

std::vector<Bytes> sampleRouterInfos(std::size_t count);

Bytes packReseedSu3(const std::vector<Bytes>& routers, const std::string& signerId);

std::size_t seedRouterInfos(
    const std::filesystem::path& dataDir, const std::vector<Bytes>& routers);

class Stream {
public:
    ~Stream();
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    void setReadTimeout(std::chrono::seconds timeout);
    std::size_t readSome(void* buffer, std::size_t size);
    void readExact(void* buffer, std::size_t size);
    void writeAll(const void* data, std::size_t size);
    std::size_t pendingBytes() const;
    void close();

private:
    Stream();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Endpoint;
};

enum class Traffic { eStream, eRaw };

struct EndpointConfig {
    std::optional<Keys> keys;
    Privacy privacy = Privacy::eMax;
    int tunnelQuantity = 3;
    bool published = true;
    std::string label = {};
    std::string owner = {};
    Traffic traffic = Traffic::eStream;
    bool realtime = false;
    bool bulk = false;
};

class Endpoint {
public:
    ~Endpoint();
    Endpoint(const Endpoint&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;

    bool ready() const;
    bool waitReady(std::chrono::seconds timeout);
    bool lost() const;

    // The shareable base64 destination (goes into a contact card).
    std::string publicBase64() const;
    std::string routingHost() const;
    Bytes privateBlob() const;

    void refreshOfflineSignature(const Keys& newTransient);

    // Open a stream to a ".b32.i2p" host (b32 or b33) or a base64 destination.
    std::unique_ptr<Stream> connect(const std::string& host, std::chrono::seconds timeout);
    std::unique_ptr<Stream> accept(std::string& peerBase64, std::chrono::seconds timeout);

    // Send one repliable datagram to a host (".b32.i2p" or base64).
    void sendDatagram(const std::string& host, const void* data, std::size_t size);
    std::vector<std::uint8_t> receiveDatagram(std::string& peerBase64,
        std::chrono::milliseconds timeout);

    void sendRawDatagram(const std::string& host, const void* data, std::size_t size);
    std::vector<std::uint8_t> receiveRawDatagram(std::chrono::milliseconds timeout);

    void stop();

private:
    Endpoint();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Router;
};

// Which engine moves the traffic.
enum class Backend { eEmbedded, eSam, eGateway };

struct Capabilities {
    bool routerCounters = false;
    bool destinationCounters = false;
    bool netDbSample = false;
    bool proxy = false;
    bool offlineKeys = false;
};

inline constexpr int kDefaultSamControlPort = 7656;

struct RouterConfig {
    // All router state nests under this directory (netDb, peerProfiles, destinations, keys, logs).
    std::filesystem::path dataDir;
    Role role = Role::eClient;
    std::vector<std::string> reseedUrls{};
    std::string socksProxyHost{};
    int socksProxyPort = 0;
    Backend backend = Backend::eEmbedded;
    std::string samHost = "127.0.0.1";
    int samControlPort = kDefaultSamControlPort;
    int samDatagramPort = 0;
    std::string gatewayHost;
    int gatewayPort = 0;
    std::string gatewayPath;
    std::string gatewayToken;
    std::string gatewayPin;
    bool gatewayTls = true;
    std::chrono::milliseconds gatewayDecoyMin{0};
    std::chrono::milliseconds gatewayDecoyMax{0};
    std::chrono::seconds gatewayControlMinLife{0};
    std::chrono::seconds gatewayControlMaxLife{0};
    std::chrono::seconds gatewayControlMaxGap{0};
};

struct ProxyState {
    std::string ntcp2;
    std::string ssu2;
    std::string reseed;
    bool ssu2Enabled = true;
};

struct LocalDestination {
    std::string label;
    std::string owner;
    std::string host;
    bool published = false;
    bool ready = false;
    bool closing = false;
    int inboundTunnels = 0;
    int outboundTunnels = 0;
    int remoteLeaseSets = 0;
};

struct TransportPeer {
    std::string ident;
    std::string transport;
    std::string endpoint;
    bool outbound = false;
};

void setI2pLogging(bool enabled);
bool i2pLogging();

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
    ProxyState proxyState() const;

    Capabilities capabilities() const;

    std::shared_ptr<Endpoint> createEndpoint(const EndpointConfig& config);
    // Re-file a destination under what it is being used for now.
    void retagEndpoint(const Endpoint& endpoint, std::string label, std::string owner);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::i2p
