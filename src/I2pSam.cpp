// Bazarish project (c) 2026
#include "I2pBackend.hpp"

#include "bazarish/I2pAddress.hpp"
#include "bazarish/Log.hpp"
#include "bazarish/Sam.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace bazarish::i2p {

namespace {

constexpr auto kDestinationReadyTimeout = std::chrono::seconds(180);

constexpr auto kProbeInterval = std::chrono::seconds(5);

constexpr auto kDialRetryDelay = std::chrono::seconds(2);

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
    address.datagramPort = static_cast<std::uint16_t>(config.samDatagramPort);
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
    return session;
}

class SamStream final : public backend::StreamBackend {
public:
    explicit SamStream(std::unique_ptr<sam::Stream> stream) : stream_(std::move(stream)) {}

    void setReadTimeout(const std::chrono::seconds timeout) override
    {
        stream_->setReadTimeout(static_cast<int>(timeout.count()));
    }
    std::size_t readSome(void* buffer, const std::size_t size) override
    {
        return stream_->readSome(buffer, size);
    }
    void writeAll(const void* data, const std::size_t size) override
    {
        stream_->writeAll(data, size);
    }
    std::size_t pendingBytes() const override { return stream_->pendingBytes(); }
    void close() override { stream_->close(); }

private:
    std::unique_ptr<sam::Stream> stream_;
};

class SamEndpoint final : public backend::EndpointBackend {
public:
    SamEndpoint(sam::RouterAddress router, const EndpointConfig& config)
        : router_(std::move(router))
        , config_(config)
        , publicDestination_(config.keys.value().publicBase64())
        , hostAddress_(i2p::routingHost(publicDestination_))
        , keysBlob_(config.keys.value().blob())
        , label_(config.label)
    {
        builder_ = std::thread([this]() { build(); });
    }

    ~SamEndpoint() override
    {
        if (builder_.joinable()) {
            builder_.join();
        }
        bazarish::log::info("i2p: closing destination {} ({})",
            label_.empty() ? std::string("unnamed") : label_, hostAddress_);
    }

    bool ready() const override
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return streams_ != nullptr && streams_->alive();
    }

    std::string publicBase64() const override { return publicDestination_; }
    std::string routingHost() const override { return hostAddress_; }
    Bytes privateBlob() const override { return keysBlob_; }

    void refreshOfflineSignature(const Keys&) override
    {
        notWithAnExternalRouter("swapping an offline transient");
    }

    void stop() override
    {
        stopped_.store(true);
        ready_.notify_all();
    }

    std::unique_ptr<backend::StreamBackend> connect(
        const std::string& host, const std::chrono::seconds timeout) override
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        const std::shared_ptr<sam::Session> session = waitForStreams(timeout);
        if (session == nullptr) {
            return nullptr;
        }
        while (std::chrono::steady_clock::now() < deadline && !stopped_) {
            const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
                deadline - std::chrono::steady_clock::now());
            try {
                return std::make_unique<SamStream>(session->connect(host, remaining));
            } catch (const sam::Error& error) {
                if (error.result() != sam::Result::eCantReachPeer) {
                    bazarish::log::warn("i2p: no stream to {}: {}", host, error.what());
                    return nullptr;
                }
                bazarish::log::info("i2p: {} not found yet, trying again", host);
            }
            std::this_thread::sleep_for(kDialRetryDelay);
        }
        bazarish::log::warn("i2p: no route to {} inside the dial window", host);
        return nullptr;
    }

    std::unique_ptr<backend::StreamBackend> accept(
        std::string& peerBase64, const std::chrono::seconds timeout) override
    {
        const std::shared_ptr<sam::Session> session = waitForStreams(timeout);
        if (session == nullptr) {
            return nullptr;
        }
        session->listen();
        std::unique_ptr<sam::Stream> stream = session->accept(peerBase64,
            timeout.count() == 0 ? std::chrono::milliseconds::max()
                                 : std::chrono::duration_cast<std::chrono::milliseconds>(timeout));
        if (stream == nullptr) {
            return nullptr;
        }
        return std::make_unique<SamStream>(std::move(stream));
    }

    void sendDatagram(
        const std::string& host, const void* data, const std::size_t size) override
    {
        datagrams(sam::Style::eDatagram)->sendDatagram(host, data, size);
    }

    std::vector<std::uint8_t> receiveDatagram(
        std::string& peerBase64, const std::chrono::milliseconds timeout) override
    {
        return datagrams(sam::Style::eDatagram)->receiveDatagram(&peerBase64, timeout);
    }

    void sendRawDatagram(
        const std::string& host, const void* data, const std::size_t size) override
    {
        datagrams(sam::Style::eRaw)->sendDatagram(host, data, size);
    }

    std::vector<std::uint8_t> receiveRawDatagram(
        const std::chrono::milliseconds timeout) override
    {
        return datagrams(sam::Style::eRaw)->receiveDatagram(nullptr, timeout);
    }

    std::string label() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return label_;
    }

    std::string owner() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return owner_;
    }

    void retag(std::string label, std::string owner)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        label_ = std::move(label);
        owner_ = std::move(owner);
    }

    bool published() const { return config_.published; }

private:
    void build()
    {
        try {
            auto session = std::make_shared<sam::Session>(
                router_, sessionConfigFor(config_, sam::Style::eStream), kDestinationReadyTimeout);
            const std::lock_guard<std::mutex> lock(mutex_);
            streams_ = std::move(session);
        } catch (const std::exception& error) {
            const std::lock_guard<std::mutex> lock(mutex_);
            failure_ = error.what();
            bazarish::log::warn("i2p: destination {} did not come up: {}",
                label_.empty() ? std::string("unnamed") : label_, failure_);
        }
        ready_.notify_all();
    }

    std::shared_ptr<sam::Session> waitForStreams(const std::chrono::seconds timeout)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const auto arrived = [this] {
            return streams_ != nullptr || !failure_.empty() || stopped_;
        };
        if (timeout.count() == 0) {
            ready_.wait(lock, arrived);
        } else if (!ready_.wait_for(lock, timeout, arrived)) {
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
    const Bytes keysBlob_;

    std::atomic<bool> stopped_{false};

    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::shared_ptr<sam::Session> streams_;
    std::string failure_;
    std::string label_;
    std::string owner_;
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
            entry.owner = endpoint->owner();
            entry.host = endpoint->routingHost();
            entry.published = endpoint->published();
            entry.ready = endpoint->ready();
            destinations.push_back(std::move(entry));
        }
        return destinations;
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
        endpoint->retag(config.label, config.owner);
        return endpoint;
    }

    void retagEndpoint(const backend::EndpointBackend& endpoint, std::string label,
        std::string owner) override
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const std::weak_ptr<SamEndpoint>& held : endpoints_) {
            const std::shared_ptr<SamEndpoint> mine = held.lock();
            if (mine != nullptr && mine.get() == &endpoint) {
                mine->retag(std::move(label), std::move(owner));
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
