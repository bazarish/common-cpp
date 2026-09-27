// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include <chrono>
#include <filesystem>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace bazarish::i2p::backend {

// What the public facade delegates to. Two implementations: the engine inside
// this process, and a router outside it reached over SAM. The split is here and
// not in the header because it is nobody's business but this library's - a
// caller writes the same code either way.

class StreamBackend {
public:
    virtual ~StreamBackend() = default;

    virtual void setReadTimeout(std::chrono::seconds timeout) = 0;
    virtual std::size_t readSome(void* buffer, std::size_t size) = 0;
    virtual void writeAll(const void* data, std::size_t size) = 0;
    virtual std::size_t pendingBytes() const = 0;
    virtual void close() = 0;
};

class EndpointBackend {
public:
    virtual ~EndpointBackend() = default;

    virtual bool ready() const = 0;
    // True when this destination is gone for good, so waiting for it to be ready
    // again is waiting for nothing. Only a borrowed destination can be taken away:
    // an engine in this process keeps its own until its owner stops it.
    virtual bool lost() const { return false; }
    virtual std::string publicBase64() const = 0;
    virtual std::string routingHost() const = 0;
    virtual Bytes privateBlob() const = 0;
    virtual void refreshOfflineSignature(const Keys& newTransient) = 0;

    virtual std::unique_ptr<StreamBackend> connect(
        const std::string& host, std::chrono::seconds timeout)
        = 0;
    virtual std::unique_ptr<StreamBackend> accept(
        std::string& peerBase64, std::chrono::seconds timeout)
        = 0;

    virtual void sendDatagram(const std::string& host, const void* data, std::size_t size) = 0;
    virtual std::vector<std::uint8_t> receiveDatagram(
        std::string& peerBase64, std::chrono::milliseconds timeout)
        = 0;
    virtual void sendRawDatagram(const std::string& host, const void* data, std::size_t size) = 0;
    virtual std::vector<std::uint8_t> receiveRawDatagram(std::chrono::milliseconds timeout) = 0;

    virtual void stop() = 0;
};

class RouterBackend {
public:
    virtual ~RouterBackend() = default;

    virtual Capabilities capabilities() const = 0;

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual bool running() const = 0;
    virtual bool ready() const = 0;

    virtual int knownRouters() const = 0;
    virtual int floodfills() const = 0;
    virtual int transitTunnels() const = 0;
    virtual int inboundTunnels() const = 0;
    virtual int outboundTunnels() const = 0;
    virtual std::vector<TransportPeer> transportPeers() const = 0;
    virtual std::vector<LocalDestination> localDestinations() const = 0;

    virtual void setSocksProxy(const std::string& host, int port) = 0;
    virtual ProxyState proxyState() const = 0;

    virtual Keys generateKeys() = 0;
    virtual std::shared_ptr<EndpointBackend> createEndpoint(const EndpointConfig& config) = 0;
    virtual void retagEndpoint(
        const EndpointBackend& endpoint, std::string label, std::string owner)
        = 0;
};

// Built in the transport's own translation unit, so the facade holds no engine.
std::unique_ptr<RouterBackend> makeSamRouter(const RouterConfig& config);
std::unique_ptr<RouterBackend> makeGatewayRouter(const RouterConfig& config);

#ifdef BAZARISH_WITH_I2PD
std::unique_ptr<RouterBackend> makeEmbeddedRouter(const RouterConfig& config);
// The engine's own answers, which only it has.
std::string embeddedRouterVersion();
std::vector<Bytes> embeddedSampleRouterInfos(std::size_t count);
std::size_t embeddedSeedRouterInfos(
    const std::filesystem::path& dataDir, const std::vector<Bytes>& routers);
// Key material the embedded engine mints. Kept behind these two calls because
// they are the whole of what a build without the engine cannot do.
Bytes generateKeysBlob();
Bytes issueTransientBlob(const Bytes& master, int days);
int b33OfflineKeyDays(const Bytes& blob);
#endif

}  // namespace bazarish::i2p::backend
