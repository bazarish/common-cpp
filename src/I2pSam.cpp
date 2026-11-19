// Bazarish project (c) 2026
#include "I2pBackend.hpp"

#include "bazarish/I2pAddress.hpp"
#include "bazarish/Log.hpp"
#include "bazarish/Sam.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace bazarish::i2p {

using backend::DestTag;

namespace {

constexpr auto kDestinationReadyTimeout = std::chrono::seconds(180);
constexpr auto kHeldDestinationRetry = std::chrono::seconds(5);

constexpr auto kProbeInterval = std::chrono::seconds(5);

[[noreturn]] void notWithAnExternalRouter(const std::string& what)
{
    throw std::runtime_error(
        "bazarish::i2p: " + what + " is not available with an external router");
}

sam::RouterAddress addressOf(const RouterConfig& config)
{
    sam::RouterAddress address;
    address.host = config.samHost;
    address.controlPort = static_cast<std::uint16_t>(config.samControlPort);
    return address;
}

sam::SessionConfig sessionConfigFor(const EndpointConfig& config, const sam::Style style)
{
    sam::SessionConfig session;
    session.privateKeys = config.keys.value().privateBase64();
    session.style = style;
    session.privacy = config.privacy;
    session.tunnelQuantity = config.tunnelQuantity;
    session.published = config.published;
    session.blinded = config.blinded;
    for (const Bytes& reader : config.leaseSetReaders) {
        session.leaseSetReaders.push_back(backend::leaseSetKeyBase64(reader));
    }
    if (!config.leaseSetReaderKey.empty()) {
        session.leaseSetReaderKey = backend::leaseSetKeyBase64(config.leaseSetReaderKey);
    }
    return session;
}

class SamStream final : public backend::StreamBackend {
public:
    explicit SamStream(std::shared_ptr<sam::Stream> stream) : stream_(std::move(stream)) {}

    void setReadTimeout(const std::chrono::seconds timeout) override
    {
        stream_->setReadTimeout(static_cast<int>(timeout.count()));
    }
    std::size_t readSome(const ByteBuffer buffer) override
    {
        const std::size_t got = stream_->readSome(buffer);
        if (got > 0) {
            answered_.store(true);
        }
        return got;
    }
    void writeAll(const ByteView data) override { stream_->writeAll(data); }
    std::size_t pendingBytes() const override { return stream_->pendingBytes(); }
    void close() override { stream_->close(); }
    bool answered() const override { return answered_.load(); }

private:
    std::shared_ptr<sam::Stream> stream_;
    std::atomic<bool> answered_{false};
};

class SamEndpoint final : public backend::EndpointBackend {
public:
    SamEndpoint(sam::RouterAddress router, const EndpointConfig& config)
        : router_(std::move(router))
        , config_(config)
        , publicDestination_(config.keys.value().publicBase64())
        , hostAddress_(i2p::routingHost(publicDestination_, config.blinded))
        , tag_(config.label, config.accountLabel)
    {
        builder_ = std::thread([this]() { build(); });
    }

    ~SamEndpoint() override
    {
        stop();
        if (builder_.joinable()) {
            builder_.join();
        }
        bazarish::log::info("i2p: closing destination {} ({})",
            tag_.named(), hostAddress_);
    }

    bool ready() const override
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return streams_ != nullptr && streams_->alive();
    }

    // A session the router dropped, or one that never came up, is not rebuilt here.
    bool lost() const override
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return stopped_.load() || !failure_.empty() || (streams_ != nullptr && !streams_->alive());
    }
    std::string publicBase64() const override { return publicDestination_; }
    std::string routingHost() const override { return hostAddress_; }

    void refreshOfflineSignature(const Keys&) override
    {
        notWithAnExternalRouter("swapping an offline transient");
    }

    void setLeaseSetReaderKey(const Bytes&) override
    {
        notWithAnExternalRouter("a lease-set reader key after the session is made");
    }

    // A stopped destination wakes its streams: a held read has no deadline of its own.
    void stop() override
    {
        std::vector<std::shared_ptr<sam::Stream>> open;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            stopped_.store(true);
            for (const std::weak_ptr<sam::Stream>& held : open_) {
                if (std::shared_ptr<sam::Stream> stream = held.lock()) {
                    open.push_back(std::move(stream));
                }
            }
            open_.clear();
        }
        for (const std::shared_ptr<sam::Stream>& stream : open) {
            stream->interrupt();
        }
        ready_.notify_all();
        stateSignal->changed();
    }

    std::unique_ptr<backend::StreamBackend> connect(
        const std::string& host, const std::chrono::seconds timeout) override
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        const std::shared_ptr<sam::Session> session = waitForStreams(timeout);
        if (session == nullptr || stopped_) {
            return nullptr;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) {
            return nullptr;
        }
        try {
            std::shared_ptr<sam::Stream> stream = session->connect(host, remaining);
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                if (stopped_) {
                    return nullptr;
                }
                std::erase_if(open_, [](const std::weak_ptr<sam::Stream>& held) { return held.expired(); });
                open_.push_back(stream);
            }
            return std::make_unique<SamStream>(std::move(stream));
        } catch (const sam::Error& error) {
            bazarish::log::warn("i2p: no stream to {}: {}", host, error.what());
            return nullptr;
        }
    }

    std::unique_ptr<backend::StreamBackend> accept(
        std::string& peerBase64, const std::chrono::seconds timeout) override
    {
        const std::shared_ptr<sam::Session> session = waitForStreams(timeout);
        if (session == nullptr) {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (!failure_.empty()) {
                throw std::runtime_error("bazarish::i2p: destination " + tag_.named()
                    + " did not come up: " + failure_);
            }
            return nullptr;
        }
        session->listen();
        std::unique_ptr<sam::Stream> stream = session->accept(
            peerBase64, std::chrono::duration_cast<std::chrono::milliseconds>(timeout));
        if (stream == nullptr) {
            return nullptr;
        }
        return std::make_unique<SamStream>(std::move(stream));
    }

    void sendDatagram(const std::string& host, const ByteView data) override
    {
        datagrams(sam::Style::eDatagram)->sendDatagram(host, data);
    }

    Datagram receiveDatagram(const std::chrono::milliseconds timeout) override
    {
        return datagrams(sam::Style::eDatagram)->receiveDatagram(timeout);
    }

    void sendRawDatagram(const std::string& host, const ByteView data) override
    {
        datagrams(sam::Style::eRaw)->sendDatagram(host, data);
    }

    std::vector<std::uint8_t> receiveRawDatagram(
        const std::chrono::milliseconds timeout) override
    {
        return datagrams(sam::Style::eRaw)->receiveDatagram(timeout).data;
    }

    std::string label() const { return tag_.label(); }

    std::string accountLabel() const { return tag_.accountLabel(); }

    void retag(std::string label, std::string accountLabel)
    {
        tag_.retag(std::move(label), std::move(accountLabel));
    }

    bool published() const { return config_.published; }

private:
    void build()
    {
        try {
            for (bool told = false;;) {
                try {
                    auto session = std::make_shared<sam::Session>(router_,
                        sessionConfigFor(config_, sam::Style::eStream), kDestinationReadyTimeout,
                        [signal = stateSignal]() { signal->changed(); });
                    const std::lock_guard<std::mutex> lock(mutex_);
                    streams_ = std::move(session);
                    break;
                } catch (const sam::Error& error) {
                    if (error.result() != sam::Result::eDuplicatedDest) {
                        throw;
                    }
                    if (!told) {
                        bazarish::log::info("i2p: destination {} is still held by the router; "
                                            "waiting for it to let go",
                            tag_.named());
                        told = true;
                    }
                }
                std::unique_lock<std::mutex> lock(mutex_);
                if (ready_.wait_for(lock, kHeldDestinationRetry, [this] { return stopped_.load(); })) {
                    return;
                }
            }
        } catch (const std::exception& error) {
            const std::lock_guard<std::mutex> lock(mutex_);
            failure_ = error.what();
            bazarish::log::warn("i2p: destination {} did not come up: {}",
                tag_.named(), failure_);
        }
        ready_.notify_all();
        stateSignal->changed();
    }

    std::shared_ptr<sam::Session> waitForStreams(const std::chrono::seconds timeout)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const auto arrived = [this] {
            return streams_ != nullptr || !failure_.empty() || stopped_;
        };
        if (!ready_.wait_for(lock, timeout, arrived)) {
            return nullptr;
        }
        return stopped_ ? nullptr : streams_;
    }

    std::shared_ptr<sam::Session> datagrams(const sam::Style style)
    {
        const std::lock_guard<std::mutex> lock(datagramMutex_);
        std::shared_ptr<sam::Session>& session
            = style == sam::Style::eRaw ? raw_ : repliable_;
        if (session == nullptr) {
            session = std::make_shared<sam::Session>(
                router_, sessionConfigFor(config_, style), kDestinationReadyTimeout);
        }
        return session;
    }

    const sam::RouterAddress router_;
    const EndpointConfig config_;
    const std::string publicDestination_;
    const std::string hostAddress_;

    std::atomic<bool> stopped_{false};

    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::shared_ptr<sam::Session> streams_;
    std::vector<std::weak_ptr<sam::Stream>> open_;
    std::string failure_;
    DestTag tag_;
    std::thread builder_;

    std::mutex datagramMutex_;
    std::shared_ptr<sam::Session> repliable_;
    std::shared_ptr<sam::Session> raw_;
};

class SamRouter final : public backend::RouterBackend {
public:
    explicit SamRouter(const RouterConfig& config) : address_(addressOf(config))
    {
        start();
    }

    Capabilities capabilities() const override
    {
        return Capabilities{};
    }

    void start() override
    {
        (void)sam::probe(address_);
        running_ = true;
        probedAt_ = std::chrono::steady_clock::now();
        reachable_ = true;
        bazarish::log::info("i2p: using the router at {}:{} over SAM", address_.host,
            address_.controlPort);
    }

    void stop() override
    {
        running_ = false;
        reachable_ = false;
    }

    bool running() const override { return running_; }

    // Nothing tells when a SAM bridge starts answering: a probe answers now or the wait fails.
    bool waitReady(
        std::chrono::steady_clock::time_point, const std::stop_token&) override
    {
        return ready();
    }

    bool ready() const override
    {
        if (!running_) {
            return false;
        }
        const auto now = std::chrono::steady_clock::now();
        const std::lock_guard<std::mutex> lock(probeMutex_);
        if (now - probedAt_ < kProbeInterval) {
            return reachable_;
        }
        probedAt_ = now;
        try {
            (void)sam::probe(address_);
            reachable_ = true;
        } catch (const std::exception& error) {
            bazarish::log::warn("i2p: the router at {}:{} did not answer: {}", address_.host,
                address_.controlPort, error.what());
            reachable_ = false;
        }
        return reachable_;
    }

    int knownRouters() const override { notWithAnExternalRouter("the netDb count"); }
    int floodfills() const override { notWithAnExternalRouter("the floodfill count"); }
    int transitTunnels() const override { notWithAnExternalRouter("transit tunnels"); }
    int inboundTunnels() const override { notWithAnExternalRouter("tunnel counts"); }
    int outboundTunnels() const override { notWithAnExternalRouter("tunnel counts"); }

    std::vector<TransportPeer> transportPeers() const override
    {
        notWithAnExternalRouter("the transport peer list");
    }

    std::vector<LocalDestination> localDestinations() const override
    {
        std::vector<LocalDestination> destinations;
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const std::weak_ptr<SamEndpoint>& held : endpoints_) {
            const std::shared_ptr<SamEndpoint> endpoint = held.lock();
            if (endpoint == nullptr) {
                continue;
            }
            LocalDestination entry;
            entry.label = endpoint->label();
            entry.accountLabel = endpoint->accountLabel();
            entry.host = endpoint->routingHost();
            entry.published = endpoint->published();
            entry.ready = endpoint->ready();
            destinations.push_back(std::move(entry));
        }
        return destinations;
    }

    std::optional<DestinationDetail> destinationDetail(const std::string&) const override
    {
        notWithAnExternalRouter("a destination's tunnels and lease sets");
    }

    LeaseSetRefresh refreshLeaseSet(const std::string&, const std::string&) override
    {
        notWithAnExternalRouter("refreshing a lease set");
    }

    void setSocksProxy(const std::string&, int) override
    {
        notWithAnExternalRouter("the clearnet proxy");
    }

    void setReseedUrls(const std::vector<std::string>&) override
    {
        notWithAnExternalRouter("a reseed");
    }

    ReseedState reseedState() const override
    {
        notWithAnExternalRouter("a reseed");
    }

    ProxyState proxyState() const override { notWithAnExternalRouter("the clearnet proxy"); }

    std::shared_ptr<backend::EndpointBackend> createEndpoint(
        const EndpointConfig& config) override
    {
        EndpointConfig filled = config;
        if (!filled.keys.has_value()) {
            filled.keys = Keys::generate();
        }
        auto endpoint = std::make_shared<SamEndpoint>(address_, filled);
        const std::lock_guard<std::mutex> lock(mutex_);
        std::erase_if(endpoints_,
            [](const std::weak_ptr<SamEndpoint>& held) { return held.expired(); });
        endpoints_.push_back(endpoint);
        endpoint->retag(config.label, config.accountLabel);
        return endpoint;
    }

    void retagEndpoint(const backend::EndpointBackend& endpoint, std::string label,
        std::string accountLabel) override
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const std::weak_ptr<SamEndpoint>& held : endpoints_) {
            const std::shared_ptr<SamEndpoint> mine = held.lock();
            if (mine != nullptr && mine.get() == &endpoint) {
                mine->retag(std::move(label), std::move(accountLabel));
                return;
            }
        }
    }

private:
    const sam::RouterAddress address_;
    std::atomic<bool> running_{false};
    mutable std::atomic<bool> reachable_{false};
    mutable std::mutex probeMutex_;
    mutable std::chrono::steady_clock::time_point probedAt_{};

    mutable std::mutex mutex_;
    std::vector<std::weak_ptr<SamEndpoint>> endpoints_;
};

}  // namespace

namespace backend {

std::unique_ptr<RouterBackend> makeSamRouter(const RouterConfig& config)
{
    return std::make_unique<SamRouter>(config);
}

}  // namespace backend

}  // namespace bazarish::i2p
