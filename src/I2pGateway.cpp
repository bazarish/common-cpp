// Bazarish project (c) 2026
#include "I2pBackend.hpp"

#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/GatewayStreamBook.hpp"
#include "bazarish/Log.hpp"
#include "bazarish/WebSocketClient.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::i2p::backend {

namespace {

using gateway::Frame;
using gateway::FrameType;

// A stream that turns out to be carrying bulk is given a socket of its own, so
// a file stops sharing a queue with everything else. Small request-and-answer
// streams - a card fetch, a facade call - never reach this and never cost one.
constexpr std::uint64_t kOwnSocketAfterBytes = 256 * 1024;
// How long a caller waits for an answer to a request before giving up on the
// gateway rather than on the operation.
constexpr std::chrono::seconds kCallTimeout{60};
// How often a blocked reader looks again at whether anything arrived.
constexpr std::chrono::milliseconds kPoll{20};

[[noreturn]] void notWithAGateway(const char* const what)
{
    throw std::runtime_error(
        std::string("bazarish::i2p: ") + what + " is not something a gateway can answer");
}

// One request waiting for the answer that carries its reference.
struct Pending {
    std::mutex mutex;
    std::condition_variable answered;
    bool done = false;
    Frame answer;
};

class GatewayRouter;

class GatewayStream : public StreamBackend {
public:
    GatewayStream(GatewayRouter& router, std::uint32_t id);
    ~GatewayStream() override;

    void setReadTimeout(std::chrono::seconds timeout) override { readTimeout_ = timeout; }
    std::size_t readSome(void* buffer, std::size_t size) override;
    void writeAll(const void* data, std::size_t size) override;
    std::size_t pendingBytes() const override { return book_.pending(); }
    void close() override;

    std::uint32_t id() const { return id_; }
    // Bytes the gateway sent for this stream.
    void arrived(const Bytes& data);
    void creditedBy(std::uint64_t total) { book_.peerCredited(total); }
    void farSideFinished();
    void reset();

private:
    GatewayRouter& router_;
    std::uint32_t id_;
    gateway::StreamBook book_;
    std::chrono::seconds readTimeout_{0};
    mutable std::mutex mutex_;
    std::condition_variable arrived_;
    std::deque<unsigned char> inbox_;
    bool finished_ = false;
    bool closed_ = false;
};

class GatewayEndpoint : public EndpointBackend {
public:
    GatewayEndpoint(GatewayRouter& router, std::uint32_t id, std::string host, bool raw);
    ~GatewayEndpoint() override;

    bool ready() const override { return ready_.load(); }
    std::string publicBase64() const override
    {
        // The gateway minted this destination and never sent its key, so there
        // is no public form here to hand back. A caller that wants one is a
        // caller about to be wrong about something.
        notWithAGateway("the base64 of a destination the gateway minted");
    }
    std::string routingHost() const override { return host_; }
    Bytes privateBlob() const override
    {
        notWithAGateway("the private key of a destination the gateway holds");
    }
    void refreshOfflineSignature(const Keys&) override
    {
        notWithAGateway("swapping an offline transient");
    }

    std::unique_ptr<StreamBackend> connect(
        const std::string& host, std::chrono::seconds timeout) override;
    std::unique_ptr<StreamBackend> accept(
        std::string& peerBase64, std::chrono::seconds timeout) override;

    void sendDatagram(const std::string&, const void*, std::size_t) override
    {
        notWithAGateway("a repliable datagram");
    }
    std::vector<std::uint8_t> receiveDatagram(std::string&, std::chrono::milliseconds) override
    {
        notWithAGateway("a repliable datagram");
    }
    void sendRawDatagram(const std::string& host, const void* data, std::size_t size) override;
    std::vector<std::uint8_t> receiveRawDatagram(std::chrono::milliseconds timeout) override;

    void stop() override;

    std::uint32_t id() const { return id_; }
    bool raw() const { return raw_; }
    void statusChanged(bool ready, int in, int out, int leases);
    void datagramArrived(std::vector<std::uint8_t> payload);
    void callerArrived(std::unique_ptr<GatewayStream> stream, const std::string& peer);
    int inboundTunnels() const { return in_.load(); }
    int outboundTunnels() const { return out_.load(); }
    int leaseSets() const { return leases_.load(); }

private:
    GatewayRouter& router_;
    std::uint32_t id_;
    std::string host_;
    bool raw_;
    std::atomic<bool> ready_{false};
    std::atomic<bool> stopped_{false};
    std::atomic<int> in_{0};
    std::atomic<int> out_{0};
    std::atomic<int> leases_{0};
    mutable std::mutex mutex_;
    std::condition_variable arrived_;
    std::deque<std::vector<std::uint8_t>> datagrams_;
    std::deque<std::pair<std::unique_ptr<GatewayStream>, std::string>> callers_;
};

class GatewayRouter : public RouterBackend {
public:
    explicit GatewayRouter(const RouterConfig& config)
        : config_(config)
        , ids_(/*odd=*/false)
    {
    }

    ~GatewayRouter() override { stop(); }

    Capabilities capabilities() const override
    {
        Capabilities what;
        // The gateway's own router answers these, and they are what the
        // connection progress and the status view read. They describe a machine
        // the user chose, and the view says so.
        what.routerCounters = true;
        what.destinationCounters = true;
        // A slice of the netDb is what a server packs into a private reseed,
        // and a client never asks for one.
        what.netDbSample = false;
        // The gateway's clearnet side is its operator's configuration.
        what.proxy = false;
        // No client destination is offline-keyed: the one that is belongs to a
        // server and is never operated here.
        what.offlineKeys = false;
        return what;
    }

    void start() override;
    void stop() override;
    bool running() const override { return socket_ != nullptr && socket_->open(); }
    bool ready() const override { return running(); }

    int knownRouters() const override { return known_.load(); }
    int floodfills() const override { return floodfills_.load(); }
    int transitTunnels() const override { return 0; }
    int inboundTunnels() const override { return inbound_.load(); }
    int outboundTunnels() const override { return outbound_.load(); }
    std::vector<TransportPeer> transportPeers() const override { return {}; }
    std::vector<LocalDestination> localDestinations() const override;

    void setSocksProxy(const std::string&, int) override
    {
        notWithAGateway("the clearnet proxy");
    }
    ProxyState proxyState() const override { notWithAGateway("the clearnet proxy"); }

    Keys generateKeys() override;
    std::shared_ptr<EndpointBackend> createEndpoint(const EndpointConfig& config) override;
    void retagEndpoint(const EndpointBackend&, std::string, std::string) override {}

    // --- what the endpoints and streams use ---

    std::uint32_t nextId() { return ids_.next(); }
    void send(const Bytes& frame);
    // Sends and waits for the answer that carries the same reference.
    Frame call(const Bytes& frame, std::uint32_t ref, std::chrono::seconds timeout);
    void forget(std::uint32_t id);
    // A stream is owned by whoever asked for it, so the router holds a pointer
    // and the stream says when it goes.
    void remember(std::uint32_t id, GatewayStream* stream);
    // Gives a flow a socket of its own, once it is worth one.
    void attach(std::uint32_t flow, std::uint64_t received);
    http::SocketPtr socketFor(std::uint32_t flow) const;

private:
    void arrived(const http::SocketPtr& socket, const std::vector<unsigned char>& message);
    void dispatch(const Frame& frame);
    http::SocketDial dialFor() const;

    RouterConfig config_;
    gateway::Ids ids_;
    http::SocketPtr socket_;
    std::string cookie_;
    mutable std::mutex mutex_;
    std::map<std::uint32_t, std::shared_ptr<Pending>> pending_;
    std::map<std::uint32_t, std::weak_ptr<GatewayEndpoint>> endpoints_;
    std::map<std::uint32_t, GatewayStream*> streams_;
    std::map<std::uint32_t, http::SocketPtr> flows_;
    std::atomic<int> known_{0};
    std::atomic<int> floodfills_{0};
    std::atomic<int> inbound_{0};
    std::atomic<int> outbound_{0};
};

// --- stream ---

GatewayStream::GatewayStream(GatewayRouter& router, const std::uint32_t id)
    : router_(router)
    , id_(id)
{
    router_.remember(id_, this);
}

GatewayStream::~GatewayStream()
{
    close();
    router_.remember(id_, nullptr);
}

void GatewayStream::arrived(const Bytes& data)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        inbox_.insert(inbox_.end(), data.begin(), data.end());
    }
    book_.tookIn(data.size());
    arrived_.notify_all();
}

void GatewayStream::farSideFinished()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        finished_ = true;
    }
    book_.peerFinished();
    arrived_.notify_all();
}

void GatewayStream::reset()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        finished_ = true;
        closed_ = true;
    }
    arrived_.notify_all();
}

std::size_t GatewayStream::readSome(void* const buffer, const std::size_t size)
{
    std::unique_lock<std::mutex> lock(mutex_);
    const auto deadline = readTimeout_.count() > 0
        ? std::chrono::steady_clock::now() + readTimeout_
        : std::chrono::steady_clock::time_point::max();
    while (inbox_.empty() && !finished_ && !closed_) {
        if (arrived_.wait_until(lock, deadline) == std::cv_status::timeout) {
            throw std::runtime_error("bazarish::i2p: the stream said nothing in time");
        }
    }
    if (inbox_.empty()) {
        return 0;  // the far side is done, or this one is
    }
    const std::size_t got = std::min(size, inbox_.size());
    unsigned char* const at = static_cast<unsigned char*>(buffer);
    std::copy(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(got), at);
    inbox_.erase(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(got));
    lock.unlock();

    // Read means consumed, and a credit is the total consumed so far.
    book_.consumed(got);
    router_.send(gateway::encodeCredit(id_, book_.consumedTotal()));
    if (book_.received() > kOwnSocketAfterBytes) {
        router_.attach(id_, book_.received());
    }
    return got;
}

void GatewayStream::writeAll(const void* const data, const std::size_t size)
{
    const unsigned char* at = static_cast<const unsigned char*>(data);
    std::size_t left = size;
    while (left > 0) {
        // Never more than the window the gateway granted, and never more than
        // one message: a message cannot be interleaved with another, so its
        // length is how long anything else waits behind it.
        while (book_.room() == 0) {
            if (closed_) {
                throw std::runtime_error("bazarish::i2p: the stream is closed");
            }
            std::this_thread::sleep_for(kPoll);
        }
        const std::size_t piece = std::min({left, book_.room(), gateway::kMaxBodyBytes});
        book_.wrote(at, piece);
        const http::SocketPtr out = router_.socketFor(id_);
        const Bytes frame = gateway::encode(FrameType::eStreamData, id_, at, piece);
        if (out) {
            out->send(frame);
        } else {
            router_.send(frame);
        }
        at += piece;
        left -= piece;
    }
    if (book_.sent() > kOwnSocketAfterBytes) {
        router_.attach(id_, book_.received());
    }
}

void GatewayStream::close()
{
    bool tell = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        tell = !closed_;
        closed_ = true;
    }
    if (tell) {
        book_.finishSending();
        router_.send(gateway::encode(FrameType::eStreamClose, id_));
        router_.forget(id_);
    }
    arrived_.notify_all();
}

// --- endpoint ---

GatewayEndpoint::GatewayEndpoint(
    GatewayRouter& router, const std::uint32_t id, std::string host, const bool raw)
    : router_(router)
    , id_(id)
    , host_(std::move(host))
    , raw_(raw)
{
}

GatewayEndpoint::~GatewayEndpoint()
{
    stop();
}

void GatewayEndpoint::statusChanged(
    const bool isReady, const int in, const int out, const int leases)
{
    ready_.store(isReady);
    in_.store(in);
    out_.store(out);
    leases_.store(leases);
}

void GatewayEndpoint::datagramArrived(std::vector<std::uint8_t> payload)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        datagrams_.push_back(std::move(payload));
        while (datagrams_.size() > gateway::kDatagramQueue) {
            datagrams_.pop_front();
        }
    }
    arrived_.notify_all();
}

void GatewayEndpoint::callerArrived(
    std::unique_ptr<GatewayStream> stream, const std::string& peer)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        callers_.emplace_back(std::move(stream), peer);
        while (callers_.size() > gateway::kInboundQueue) {
            callers_.front().first->reset();
            callers_.pop_front();
        }
    }
    arrived_.notify_all();
}

std::unique_ptr<StreamBackend> GatewayEndpoint::connect(
    const std::string& host, const std::chrono::seconds timeout)
{
    if (stopped_.load()) {
        return nullptr;
    }
    const std::uint32_t id = router_.nextId();
    auto stream = std::make_unique<GatewayStream>(router_, id);
    const Bytes ask = gateway::encodeJson(FrameType::eStreamOpen, id,
        {{"endpoint", id_}, {"host", host}, {"deadline", timeout.count()}});
    // The whole deadline travels: the gateway re-issues the dial until it runs
    // out, because a LeaseSet that is not in the netDb yet is a reason to try
    // again rather than to fail.
    const Frame answer = router_.call(ask, id, timeout + kCallTimeout);
    if (answer.type != FrameType::eStreamOpened) {
        return nullptr;
    }
    return stream;
}

std::unique_ptr<StreamBackend> GatewayEndpoint::accept(
    std::string& peerBase64, const std::chrono::seconds timeout)
{
    std::unique_lock<std::mutex> lock(mutex_);
    const auto deadline = timeout.count() > 0
        ? std::chrono::steady_clock::now() + timeout
        : std::chrono::steady_clock::time_point::max();
    while (callers_.empty() && !stopped_.load()) {
        if (arrived_.wait_until(lock, deadline) == std::cv_status::timeout) {
            return nullptr;
        }
    }
    if (callers_.empty()) {
        return nullptr;
    }
    std::unique_ptr<GatewayStream> caller = std::move(callers_.front().first);
    peerBase64 = callers_.front().second;
    callers_.pop_front();
    return caller;
}

void GatewayEndpoint::sendRawDatagram(
    const std::string& host, const void* const data, const std::size_t size)
{
    if (stopped_.load()) {
        return;
    }
    const Bytes frame = gateway::encodeRawSend(id_, host, data, size);
    // Media rides a socket of its own, so a file cannot queue in front of it.
    // With none attached its datagrams are dropped: audio that arrives late has
    // already been played past.
    const http::SocketPtr out = router_.socketFor(id_);
    if (out) {
        out->send(frame);
    }
}

std::vector<std::uint8_t> GatewayEndpoint::receiveRawDatagram(
    const std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(mutex_);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (datagrams_.empty() && !stopped_.load()) {
        if (arrived_.wait_until(lock, deadline) == std::cv_status::timeout) {
            return {};
        }
    }
    if (datagrams_.empty()) {
        return {};
    }
    std::vector<std::uint8_t> payload = std::move(datagrams_.front());
    datagrams_.pop_front();
    return payload;
}

void GatewayEndpoint::stop()
{
    if (stopped_.exchange(true)) {
        return;
    }
    router_.send(gateway::encode(FrameType::eEndpointStop, id_));
    router_.forget(id_);
    arrived_.notify_all();
}

// --- router ---

http::SocketDial GatewayRouter::dialFor() const
{
    http::SocketDial dial;
    dial.host = config_.gatewayHost;
    dial.port = config_.gatewayPort;
    dial.path = config_.gatewayPath;
    dial.tls = config_.gatewayTls;
    dial.pin = config_.gatewayPin;
    dial.subprotocol = gateway::kSubprotocol;
    dial.maxMessageBytes = gateway::kMaxFrameBytes;
    dial.idleTimeout = gateway::kKeepalive + gateway::kPongTimeout;
    dial.headers[gateway::kTokenHeader] = config_.gatewayToken;
    if (!cookie_.empty()) {
        dial.headers[gateway::kSessionHeader] = cookie_;
    }
    return dial;
}

void GatewayRouter::start()
{
    if (running()) {
        return;
    }
    const http::SocketDialResult opened = http::openSocket(
        dialFor(),
        [this](const http::SocketPtr& socket, const std::vector<unsigned char>& message) {
            arrived(socket, message);
        },
        [this](const http::SocketPtr&) {
            const std::lock_guard<std::mutex> lock(mutex_);
            socket_.reset();
        });
    if (opened.socket == nullptr) {
        throw std::runtime_error("bazarish::i2p: the gateway would not open: " + opened.error);
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        socket_ = opened.socket;
    }

    const std::uint32_t id = nextId();
    const Frame ready = call(
        gateway::encodeJson(FrameType::eHello, id, {{"version", gateway::kProtocolVersion}}), id,
        kCallTimeout);
    if (ready.type != FrameType::eReady) {
        stop();
        throw std::runtime_error("bazarish::i2p: the gateway would not say hello");
    }
    const nlohmann::json body = gateway::bodyJson(ready);
    const std::lock_guard<std::mutex> lock(mutex_);
    cookie_ = body.value("session", std::string());
    bazarish::log::info("i2p: a gateway running i2pd {}, {}",
        body.value("i2pd", std::string("?")),
        body.value("resumed", false) ? "session rejoined" : "new session");
}

void GatewayRouter::stop()
{
    http::SocketPtr socket;
    std::vector<http::SocketPtr> flows;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        socket = socket_;
        socket_.reset();
        for (const auto& [flow, held] : flows_) {
            (void)flow;
            flows.push_back(held);
        }
        flows_.clear();
    }
    for (const http::SocketPtr& held : flows) {
        held->close();
    }
    if (socket) {
        socket->close();
    }
}

void GatewayRouter::send(const Bytes& frame)
{
    http::SocketPtr socket;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        socket = socket_;
    }
    if (socket) {
        socket->send(std::vector<unsigned char>(frame.begin(), frame.end()));
    }
}

http::SocketPtr GatewayRouter::socketFor(const std::uint32_t flow) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = flows_.find(flow);
    return found == flows_.end() ? nullptr : found->second;
}

void GatewayRouter::attach(const std::uint32_t flow, const std::uint64_t received)
{
    if (flow == 0) {
        return;
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (flows_.count(flow) > 0 || flows_.size() + 1 >= gateway::kMaxSocketsPerSession) {
            return;
        }
    }
    const http::SocketDialResult opened = http::openSocket(
        dialFor(),
        [this](const http::SocketPtr& socket, const std::vector<unsigned char>& message) {
            arrived(socket, message);
        },
        [this, flow](const http::SocketPtr&) {
            const std::lock_guard<std::mutex> lock(mutex_);
            flows_.erase(flow);
        });
    if (opened.socket == nullptr) {
        // A flow without a socket of its own rides the main one. Slower under
        // load, and not a failure.
        bazarish::log::debug("i2p: no socket of its own for flow {}: {}", flow, opened.error);
        return;
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        flows_[flow] = opened.socket;
    }
    opened.socket->send(gateway::encodeJson(FrameType::eAttach, flow, {{"received", received}}));
}

Frame GatewayRouter::call(
    const Bytes& frame, const std::uint32_t ref, const std::chrono::seconds timeout)
{
    const std::shared_ptr<Pending> pending = std::make_shared<Pending>();
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        pending_[ref] = pending;
    }
    send(frame);

    std::unique_lock<std::mutex> lock(pending->mutex);
    const bool answered = pending->answered.wait_for(lock, timeout, [&]() {
        return pending->done;
    });
    Frame answer = pending->answer;
    lock.unlock();
    {
        const std::lock_guard<std::mutex> held(mutex_);
        pending_.erase(ref);
    }
    if (!answered) {
        throw std::runtime_error("bazarish::i2p: the gateway did not answer in time");
    }
    return answer;
}

void GatewayRouter::remember(const std::uint32_t id, GatewayStream* const stream)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (stream == nullptr) {
        streams_.erase(id);
        return;
    }
    streams_[id] = stream;
}

void GatewayRouter::forget(const std::uint32_t id)
{
    http::SocketPtr flow;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        streams_.erase(id);
        endpoints_.erase(id);
        const auto found = flows_.find(id);
        if (found != flows_.end()) {
            flow = found->second;
            flows_.erase(found);
        }
    }
    if (flow) {
        flow->close();
    }
}

Keys GatewayRouter::generateKeys()
{
#ifdef BAZARISH_WITH_I2PD
    // The transport will not use this key: the gateway mints the destination's
    // own and never sends it. It is here because every caller mints before it
    // creates, and because a build with the engine can answer without asking
    // anybody.
    return Keys::fromBlob(generateKeysBlob());
#else
    notWithAGateway("minting a key without the engine");
#endif
}

std::shared_ptr<EndpointBackend> GatewayRouter::createEndpoint(const EndpointConfig& config)
{
    const std::uint32_t id = nextId();
    // In this client the two coincide exactly: raw datagrams carry a call's
    // media and nothing else, and a call's media is the only destination that
    // asks for the realtime lane. A raw destination that is not realtime would
    // need a kind of its own in the configuration.
    const bool raw = config.realtime;
    const nlohmann::json ask = {{"kind", raw ? "raw" : "stream"},
        {"privacy", privacyName(config.privacy)}, {"tunnels", config.tunnelQuantity},
        {"published", config.published}, {"realtime", config.realtime}};
    const Frame answer
        = call(gateway::encodeJson(FrameType::eEndpointCreate, id, ask), id, kCallTimeout);
    if (answer.type != FrameType::eOk) {
        throw std::runtime_error("bazarish::i2p: the gateway refused a destination");
    }
    const std::string host = gateway::bodyJson(answer).value("host", std::string());
    if (host.empty()) {
        throw std::runtime_error("bazarish::i2p: the gateway named no address");
    }
    const auto endpoint = std::make_shared<GatewayEndpoint>(*this, id, host, raw);
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        endpoints_[id] = endpoint;
    }
    if (raw) {
        // Media gets a socket of its own from the start: it is the one flow
        // that cannot wait behind anything.
        attach(id, 0);
    }
    return endpoint;
}

std::vector<LocalDestination> GatewayRouter::localDestinations() const
{
    std::vector<LocalDestination> destinations;
    const std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, held] : endpoints_) {
        (void)id;
        const std::shared_ptr<GatewayEndpoint> endpoint = held.lock();
        if (endpoint == nullptr) {
            continue;
        }
        LocalDestination entry;
        // The label and the owner never went to the gateway; the caller joins
        // its own onto this.
        entry.host = endpoint->routingHost();
        entry.ready = endpoint->ready();
        entry.inboundTunnels = endpoint->inboundTunnels();
        entry.outboundTunnels = endpoint->outboundTunnels();
        entry.remoteLeaseSets = endpoint->leaseSets();
        destinations.push_back(std::move(entry));
    }
    return destinations;
}

void GatewayRouter::arrived(
    const http::SocketPtr&, const std::vector<unsigned char>& message)
{
    try {
        dispatch(gateway::decode(message.data(), message.size()));
    } catch (const std::exception& error) {
        bazarish::log::warn("i2p: the gateway sent something unreadable: {}", error.what());
    }
}

void GatewayRouter::dispatch(const Frame& frame)
{
    // An answer is whatever carries the reference somebody is waiting on.
    std::shared_ptr<Pending> waiting;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = pending_.find(frame.ref);
        if (found != pending_.end()) {
            waiting = found->second;
        }
    }
    if (waiting != nullptr) {
        const std::lock_guard<std::mutex> lock(waiting->mutex);
        waiting->answer = frame;
        waiting->done = true;
        waiting->answered.notify_all();
        return;
    }

    if (frame.type == FrameType::eRouterStatus) {
        const nlohmann::json body = gateway::bodyJson(frame);
        known_.store(body.value("known", 0));
        floodfills_.store(body.value("floodfills", 0));
        inbound_.store(body.value("in", 0));
        outbound_.store(body.value("out", 0));
        return;
    }

    std::shared_ptr<GatewayEndpoint> endpoint;
    GatewayStream* stream = nullptr;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto atEndpoint = endpoints_.find(frame.ref);
        if (atEndpoint != endpoints_.end()) {
            endpoint = atEndpoint->second.lock();
        }
        const auto atStream = streams_.find(frame.ref);
        if (atStream != streams_.end()) {
            stream = atStream->second;
        }
    }

    switch (frame.type) {
        case FrameType::eEndpointStatus: {
            if (endpoint == nullptr) {
                return;
            }
            const nlohmann::json body = gateway::bodyJson(frame);
            endpoint->statusChanged(body.value("ready", false), body.value("tunnelsIn", 0),
                body.value("tunnelsOut", 0), body.value("leaseSets", 0));
            return;
        }
        case FrameType::eRawRecv: {
            if (endpoint != nullptr) {
                endpoint->datagramArrived(
                    std::vector<std::uint8_t>(frame.body.begin(), frame.body.end()));
            }
            return;
        }
        case FrameType::eStreamInbound: {
            const nlohmann::json body = gateway::bodyJson(frame);
            std::shared_ptr<GatewayEndpoint> on;
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                const auto found = endpoints_.find(body.value("endpoint", 0U));
                if (found != endpoints_.end()) {
                    on = found->second.lock();
                }
            }
            if (on == nullptr) {
                return;
            }
            on->callerArrived(std::make_unique<GatewayStream>(*this, frame.ref),
                body.value("peer", std::string()));
            return;
        }
        case FrameType::eStreamData:
            if (stream != nullptr) {
                stream->arrived(frame.body);
            }
            return;
        case FrameType::eStreamCredit:
            if (stream != nullptr) {
                stream->creditedBy(gateway::decodeCredit(frame));
            }
            return;
        case FrameType::eStreamClose:
            if (stream != nullptr) {
                stream->farSideFinished();
            }
            return;
        case FrameType::eStreamReset:
            if (stream != nullptr) {
                stream->reset();
            }
            return;
        case FrameType::eError: {
            const nlohmann::json body = gateway::bodyJson(frame);
            bazarish::log::warn("i2p: the gateway refused {}: {}", frame.ref,
                body.value("message", std::string()));
            return;
        }
        default:
            return;
    }
}

}  // namespace

std::unique_ptr<RouterBackend> makeGatewayRouter(const RouterConfig& config)
{
    return std::make_unique<GatewayRouter>(config);
}

}  // namespace bazarish::i2p::backend
