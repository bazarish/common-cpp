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

// How long a destination is given to come up. The router answers SESSION CREATE
// only once the destination has tunnels, so this is the whole of the wait.
constexpr auto kDestinationReadyTimeout = std::chrono::seconds(180);

// A router on this machine either answers at once or is not there. The result is
// held for a moment so a status view polling it does not open a connection per
// frame.
constexpr auto kProbeInterval = std::chrono::seconds(5);

// A destination that has just been published is not yet findable everywhere, so
// a dial that comes back "LeaseSet not found" is re-issued until the caller's
// deadline rather than reported as a failure. The embedded transport does the
// same thing for the same reason.
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
    session.privateKeys = config.keys.privateBase64();
    session.style = style;
    session.leaseSet = config.leaseSet;
    session.privacy = config.privacy;
    session.tunnelQuantity = config.tunnelQuantity;
    session.published = config.published;
    return session;
}

class SamStream final : public backend::StreamBackend {
public:
    explicit SamStream(std::unique_ptr<sam::Stream> stream) : stream_(std::move(stream)) {}

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

// One destination on the external router. A SAM session carries exactly one
// style, so a destination that both streams and sends datagrams runs two of
// them over the same keys - which the router allows, and which leave it with one
// destination either way.
class SamEndpoint final : public backend::EndpointBackend {
public:
    SamEndpoint(sam::RouterAddress router, const EndpointConfig& config)
        : router_(std::move(router))
        , config_(config)
        , publicDestination_(config.keys.publicBase64())
        , hostAddress_(i2p::routingHost(publicDestination_, config.leaseSet))
        , keysBlob_(config.keys.blob())
        , label_(config.label)
    {
        // Building tunnels takes as long as it takes, and the caller asked for a
        // destination, not for a wait: it goes up on a thread of its own, and
        // ready() says when it is there.
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
        // Swapping a live transient means re-creating the session, which drops
        // every stream on it. The router has no other way to be told.
        notWithAnExternalRouter("swapping an offline transient");
    }

    std::unique_ptr<backend::StreamBackend> connect(
        const std::string& host, const std::chrono::seconds timeout) override
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        const std::shared_ptr<sam::Session> session = waitForStreams(timeout);
        if (session == nullptr) {
            return nullptr;
        }
        while (std::chrono::steady_clock::now() < deadline) {
            const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
                deadline - std::chrono::steady_clock::now());
            try {
                return std::make_unique<SamStream>(session->connect(host, remaining));
            } catch (const sam::Error& error) {
                if (error.result() != sam::Result::eCantReachPeer) {
                    // A refusal that names the reason is an answer, not a miss:
                    // trying again with the same input would get the same one.
                    bazarish::log::warn("i2p: no stream to {}: {}", host, error.what());
                    return nullptr;
                }
                bazarish::log::info("i2p: {} not found yet, trying again", host);
            }
            std::this_thread::sleep_for(kDialRetryDelay);
        }
        // A dial that did not happen is a null stream, as it is on the embedded
        // transport.
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
        const auto arrived = [this] { return streams_ != nullptr || !failure_.empty(); };
        if (timeout.count() == 0) {
            ready_.wait(lock, arrived);
        } else if (!ready_.wait_for(lock, timeout, arrived)) {
            return nullptr;
        }
        return streams_;
    }

    // The session for a datagram style, built on first use over the same keys.
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
        // An external router says nothing about the network it is on, and its
        // clearnet side is its operator's business rather than ours.
        return Capabilities{};
    }

    void start() override
    {
        // Nothing of ours to start: the check is that the router is there at all,
        // and a router that is not there is worth saying so about now rather than
        // at the first dial.
        (void)sam::probe(address_);
        running_ = true;
        probedAt_ = std::chrono::steady_clock::now();
        reachable_ = true;
        bazarish::log::info("i2p: using the router at {}:{} over SAM", address_.host,
            address_.controlPort);
    }

    void stop() override
    {
        // The router belongs to somebody else and keeps running; what stops is
        // this process using it.
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
        // What this process runs is this process's own bookkeeping, so it can be
        // answered. The tunnel counts cannot, and stay at zero - which is what
        // capabilities() is for.
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

    ProxyState proxyState() const override { notWithAnExternalRouter("the clearnet proxy"); }

    Keys generateKeys() override
    {
        // A build with no engine cannot mint a destination, so the router does.
        const sam::Destination destination = sam::generateDestination(address_);
        return Keys::fromBlob(fromBase64(i2pToStandardBase64(destination.privateBase64)));
    }

    std::shared_ptr<backend::EndpointBackend> createEndpoint(
        const EndpointConfig& config) override
    {
        auto endpoint = std::make_shared<SamEndpoint>(address_, config);
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
