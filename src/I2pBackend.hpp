// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace bazarish::i2p::backend {

// A running destination can be renamed.
class DestTag {
public:
    DestTag(std::string label, std::string accountLabel)
        : label_(std::move(label))
        , accountLabel_(std::move(accountLabel))
    {
    }
    std::string label() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return label_;
    }
    std::string accountLabel() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return accountLabel_;
    }
    std::string named() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return label_.empty() ? std::string("unnamed") : label_;
    }
    void retag(std::string label, std::string accountLabel)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        label_ = std::move(label);
        accountLabel_ = std::move(accountLabel);
    }

private:
    mutable std::mutex mutex_;
    std::string label_;
    std::string accountLabel_;
};

// Told each time a destination's or a router's state may have changed; waiters block on it.
class StateSignal {
public:
    void changed();
    // True once done() holds; false at the deadline or once stop is requested.
    bool waitUntil(std::chrono::steady_clock::time_point deadline, const std::stop_token& stop,
        const std::function<bool()>& done);
    std::uint64_t watch(std::function<void()> listener);
    // Waits out a call already under way, so the listener's owner may go once this returns.
    void unwatch(std::uint64_t id);

private:
    std::mutex mutex_;
    std::condition_variable_any wake_;
    std::mutex listenersMutex_;
    std::mutex calling_;
    std::map<std::uint64_t, std::function<void()>> listeners_;
    std::uint64_t nextWatch_ = 0;
};

class StreamBackend {
public:
    virtual ~StreamBackend() = default;

    virtual void setReadTimeout(std::chrono::seconds timeout) = 0;
    virtual std::size_t readSome(ByteBuffer buffer) = 0;
    // Returns once the stream has taken every byte into its flow control; throws if it never will.
    virtual void writeAll(ByteView data) = 0;
    virtual std::size_t pendingBytes() const = 0;
    virtual void close() = 0;
    virtual bool answered() const = 0;
};

class EndpointBackend {
public:
    virtual ~EndpointBackend() = default;

    virtual bool ready() const = 0;
    virtual bool lost() const { return false; }
    virtual std::string publicBase64() const = 0;
    virtual std::string routingHost() const = 0;
    virtual void refreshOfflineSignature(const Keys& newTransient) = 0;
    virtual void setLeaseSetReaderKey(const Bytes& rawPrivate) = 0;

    // One attempt: null when the host's lease set is not found in time.
    virtual std::unique_ptr<StreamBackend> connect(
        const std::string& host, std::chrono::seconds timeout)
        = 0;
    virtual std::unique_ptr<StreamBackend> accept(
        std::string& peerBase64, std::chrono::seconds timeout)
        = 0;

    virtual void sendDatagram(const std::string& host, ByteView data) = 0;
    virtual Datagram receiveDatagram(std::chrono::milliseconds timeout) = 0;
    virtual void sendRawDatagram(const std::string& host, ByteView data) = 0;
    virtual std::vector<std::uint8_t> receiveRawDatagram(std::chrono::milliseconds timeout) = 0;

    virtual void stop() = 0;

    // Told whenever ready() or lost() may have changed.
    const std::shared_ptr<StateSignal> stateSignal = std::make_shared<StateSignal>();
};

class RouterBackend {
public:
    virtual ~RouterBackend() = default;

    virtual Capabilities capabilities() const = 0;

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual bool running() const = 0;
    virtual bool ready() const = 0;
    virtual bool waitReady(
        std::chrono::steady_clock::time_point deadline, const std::stop_token& stop);

    virtual int knownRouters() const = 0;
    virtual int floodfills() const = 0;
    virtual int transitTunnels() const = 0;
    virtual int inboundTunnels() const = 0;
    virtual int outboundTunnels() const = 0;
    virtual std::vector<TransportPeer> transportPeers() const = 0;
    virtual std::vector<LocalDestination> localDestinations() const = 0;
    virtual std::optional<DestinationDetail> destinationDetail(const std::string& host) const = 0;
    virtual LeaseSetRefresh refreshLeaseSet(
        const std::string& localHost, const std::string& remoteHost)
        = 0;

    virtual void setSocksProxy(const std::string& host, int port) = 0;
    virtual ProxyState proxyState() const = 0;

    virtual void setReseedUrls(const std::vector<std::string>& urls) = 0;
    virtual ReseedState reseedState() const = 0;
    virtual void repointGateway(const GatewayTarget&)
    {
        throw std::logic_error("bazarish::i2p: only a gateway router is pointed at a gateway");
    }

    virtual std::shared_ptr<EndpointBackend> createEndpoint(const EndpointConfig& config) = 0;
    virtual void retagEndpoint(
        const EndpointBackend& endpoint, std::string label, std::string accountLabel)
        = 0;

    // Told whenever ready() may have changed.
    const std::shared_ptr<StateSignal> stateSignal = std::make_shared<StateSignal>();
};

void noteCarryReturned();
void noteGatewayReach(bool reachable);

// Calls its listener on the thread that calls networkLost(), for as long as it lives.
class LossWatch {
public:
    explicit LossWatch(std::function<void()> listener);
    ~LossWatch();
    LossWatch(const LossWatch&) = delete;
    LossWatch& operator=(const LossWatch&) = delete;

private:
    const std::uint64_t id_;
};

// Calls its listener on the thread that reports the window, the screen or the user acting.
class ActivityWatch {
public:
    explicit ActivityWatch(std::function<void()> listener);
    ~ActivityWatch();
    ActivityWatch(const ActivityWatch&) = delete;
    ActivityWatch& operator=(const ActivityWatch&) = delete;

private:
    const std::uint64_t id_;
};

shape::Activity activityNow(bool exchanging);
std::uint64_t userActions();

std::unique_ptr<RouterBackend> makeSamRouter(const RouterConfig& config);
std::unique_ptr<RouterBackend> makeGatewayRouter(const RouterConfig& config);

std::unique_ptr<RouterBackend> makeEmbeddedRouter(const RouterConfig& config);
std::string embeddedRouterVersion();
void setEmbeddedLogLevel(I2pLogLevel level);
std::vector<Bytes> embeddedSampleRouterInfos(std::size_t count);
Bytes generateKeysBlob();
Bytes keysBlobFromSeeds(const Bytes& signingSeed, const Bytes& cryptoSeed);
// I2CP lease-set options take the raw X25519 key in I2P base64.
inline constexpr std::size_t kLeaseSetKeyBytes = 32;
std::string leaseSetKeyBase64(const Bytes& raw);
Bytes issueTransientBlob(const Bytes& master, int days);
std::optional<std::int64_t> offlineExpires(const Bytes& blob);
bool b33OfflineKeysCover(const Bytes& blob, std::int64_t fromUnix, std::int64_t untilUnix);

}  // namespace bazarish::i2p::backend
