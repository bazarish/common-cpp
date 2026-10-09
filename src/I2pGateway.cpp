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
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::i2p::backend {

namespace {

using gateway::Frame;
using gateway::FrameType;

constexpr std::chrono::seconds kCallTimeout{60};
constexpr std::chrono::milliseconds kCoverTick{200};
constexpr std::size_t kControlSocketsKept = 2;
constexpr std::chrono::milliseconds kQuietBeforeChurn{1000};
constexpr std::chrono::milliseconds kFirstRetry{500};
constexpr std::chrono::milliseconds kSlowestRetry{15000};
constexpr std::chrono::milliseconds kFarewellWait{2000};
constexpr std::chrono::milliseconds kFarewellPoll{20};

std::int64_t millisNow()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::uint64_t drawBetween(const std::uint64_t low, const std::uint64_t high)
{
    if (high <= low) {
        return low;
    }
    const Bytes draw = randomBytes(sizeof(std::uint64_t));
    std::uint64_t value = 0;
    for (const unsigned char byte : draw) {
        value = (value << 8) | byte;
    }
    return low + value % (high - low + 1);
}

std::chrono::milliseconds drawBetween(
    const std::chrono::milliseconds low, const std::chrono::milliseconds high)
{
    return std::chrono::milliseconds(static_cast<std::int64_t>(
        drawBetween(static_cast<std::uint64_t>(low.count()),
            static_cast<std::uint64_t>(high.count()))));
}

[[noreturn]] void notWithAGateway(const char* const what)
{
    throw std::runtime_error(
        std::string("bazarish::i2p: ") + what + " is not something a gateway can answer");
}

struct Pending {
    std::mutex mutex;
    std::condition_variable answered;
    bool done = false;
    Frame answer;
    Bytes request;
};

class GatewayStream;
class GatewayEndpoint;

class Link {
public:
    explicit Link(const bool odd) : ids_(odd) {}

    std::uint32_t nextId() { return ids_.next(); }
    void send(const Bytes& frame);
    http::SocketPtr socketFor(std::uint32_t flow) const;
    http::SocketPtr socketFor(std::uint32_t stream, std::uint32_t endpoint) const;
    Frame call(const Bytes& frame, std::uint32_t ref, std::chrono::seconds timeout);
    void forget(std::uint32_t id);
    void remember(std::uint32_t id, GatewayStream* stream);
    void endStreamsOf(std::uint32_t endpoint);

    mutable std::mutex mutex;
    gateway::Ids ids_;
    http::SocketPtr control;
    std::string cookie;
    std::map<std::uint32_t, std::shared_ptr<Pending>> awaited;
    std::map<std::uint32_t, std::weak_ptr<GatewayEndpoint>> endpoints;
    std::map<std::uint32_t, GatewayStream*> streams;
    std::map<std::uint32_t, http::SocketPtr> flows;
    std::set<std::uint32_t> orphaned;
    std::deque<Bytes> waiting;
    bool holding = false;
    std::atomic<std::int64_t> lastUse{0};
};

class GatewayRouter;

class GatewayStream : public StreamBackend {
public:
    GatewayStream(std::shared_ptr<Link> link, std::uint32_t id, std::uint32_t endpoint);
    ~GatewayStream() override;

    void setReadTimeout(std::chrono::seconds timeout) override { readTimeout_ = timeout; }
    std::size_t readSome(void* buffer, std::size_t size) override;
    void writeAll(const void* data, std::size_t size) override;
    std::size_t pendingBytes() const override;
    void close() override;

    std::uint32_t id() const { return id_; }
    std::uint32_t endpoint() const { return endpoint_; }
    void arrived(const Bytes& data);
    void creditedBy(std::uint64_t total);
    std::uint64_t received() const { return book_.received(); }
    std::uint64_t consumed() const { return book_.consumedTotal(); }
    std::vector<Bytes> replayFrames(std::uint64_t peerReceived);
    void farSideFinished();
    void reset();
    bool givenUp() const;

private:
    void drain();

    std::shared_ptr<Link> link_;
    std::uint32_t id_;
    std::uint32_t endpoint_;
    gateway::StreamBook book_;
    std::chrono::seconds readTimeout_{0};
    mutable std::mutex mutex_;
    std::condition_variable arrived_;
    std::deque<unsigned char> inbox_;
    std::deque<unsigned char> outbox_;
    bool finished_ = false;
    bool closed_ = false;
    bool endWhenDrained_ = false;
};

class GatewayEndpoint : public EndpointBackend {
public:
    GatewayEndpoint(std::shared_ptr<Link> link, std::uint32_t id, std::string host, bool raw,
        bool published, std::string label, std::string owner);
    ~GatewayEndpoint() override;

    bool ready() const override { return ready_.load(); }
    bool lost() const override { return stopped_.load(); }
    std::string publicBase64() const override
    {
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
    void mustCarryStreams() const
    {
        if (raw_) {
            notWithAGateway("a stream on a destination that carries datagrams");
        }
    }

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
    void lost();

    std::uint32_t id() const { return id_; }
    bool raw() const { return raw_; }
    bool published() const { return published_; }
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
    void statusChanged(bool ready, int in, int out, int leases);
    void datagramArrived(std::vector<std::uint8_t> payload);
    void callerArrived(std::unique_ptr<GatewayStream> stream, const std::string& peer);
    int inboundTunnels() const { return in_.load(); }
    int outboundTunnels() const { return out_.load(); }
    int leaseSets() const { return leases_.load(); }

private:
    std::shared_ptr<Link> link_;
    std::uint32_t id_;
    std::string host_;
    bool raw_;
    bool published_;
    std::string label_;
    std::string owner_;
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
        , link_(std::make_shared<Link>(/*odd=*/false))
    {
    }

    ~GatewayRouter() override { stop(); }

    Capabilities capabilities() const override
    {
        Capabilities what;
        what.routerCounters = false;
        what.destinationCounters = true;
        what.netDbSample = false;
        what.proxy = false;
        what.offlineKeys = false;
        return what;
    }

    void start() override;
    void stop() override;
    bool running() const override { return live_.load(); }
    bool ready() const override;

    int knownRouters() const override { return 0; }
    int floodfills() const override { return 0; }
    int transitTunnels() const override { return 0; }
    int inboundTunnels() const override { return 0; }
    int outboundTunnels() const override { return 0; }
    std::vector<TransportPeer> transportPeers() const override { return {}; }
    std::vector<LocalDestination> localDestinations() const override;

    void setSocksProxy(const std::string&, int) override
    {
        notWithAGateway("the clearnet proxy");
    }
    void setReseedUrls(const std::vector<std::string>&) override
    {
        notWithAGateway("a reseed");
    }

    ReseedState reseedState() const override
    {
        notWithAGateway("a reseed");
    }

    ProxyState proxyState() const override { notWithAGateway("the clearnet proxy"); }

    std::shared_ptr<EndpointBackend> createEndpoint(const EndpointConfig& config) override;
    void retagEndpoint(
        const EndpointBackend& endpoint, std::string label, std::string owner) override;

    bool attach(std::uint32_t flow, std::uint64_t received);
    void reattachOrphans();

private:
    void arrived(const http::SocketPtr& socket, const std::vector<unsigned char>& message);
    void dispatch(const Frame& frame);
    http::SocketDial dialFor() const;
    void openControl();
    void closeControl();
    void coverLoop();
    void decoy();
    bool quiet() const;
    bool hasControl() const;
    void abandon();

    RouterConfig config_;
    std::shared_ptr<Link> link_;
    std::thread cover_;
    std::atomic<bool> live_{false};
    std::atomic<std::int64_t> aloneSince_{0};
    std::atomic<bool> openFailing_{false};
};

GatewayStream::GatewayStream(
    std::shared_ptr<Link> link, const std::uint32_t id, const std::uint32_t endpoint)
    : link_(std::move(link))
    , id_(id)
    , endpoint_(endpoint)
{
    link_->remember(id_, this);
}

GatewayStream::~GatewayStream()
{
    close();
    link_->remember(id_, nullptr);
}

void GatewayStream::arrived(const Bytes& data)
{
    book_.tookIn(data.size());
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        inbox_.insert(inbox_.end(), data.begin(), data.end());
    }
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

bool GatewayStream::givenUp() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return closed_;
}

void GatewayStream::reset()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        finished_ = true;
        closed_ = true;
        outbox_.clear();
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
        return 0;
    }
    const std::size_t got = std::min(size, inbox_.size());
    unsigned char* const at = static_cast<unsigned char*>(buffer);
    std::copy(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(got), at);
    inbox_.erase(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(got));
    lock.unlock();

    book_.consumed(got);
    const Bytes credit = gateway::encodeCredit(id_, book_.consumedTotal());
    if (const http::SocketPtr own = link_->socketFor(id_, endpoint_)) {
        own->send(std::vector<unsigned char>(credit.begin(), credit.end()));
    } else {
        link_->send(credit);
    }
    return got;
}

void GatewayStream::writeAll(const void* const data, const std::size_t size)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) {
            throw std::runtime_error("bazarish::i2p: the stream is closed");
        }
        const unsigned char* const at = static_cast<const unsigned char*>(data);
        outbox_.insert(outbox_.end(), at, at + size);
    }
    drain();
}

std::vector<Bytes> GatewayStream::replayFrames(const std::uint64_t peerReceived)
{
    const Bytes again = book_.replay(peerReceived);
    std::vector<Bytes> frames;
    for (std::size_t at = 0; at < again.size(); at += gateway::kMaxBodyBytes) {
        const std::size_t piece = std::min(gateway::kMaxBodyBytes, again.size() - at);
        frames.push_back(gateway::encode(
            FrameType::eStreamData, id_, again.data() + at, piece));
    }
    return frames;
}

void GatewayStream::drain()
{
    bool ending = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const http::SocketPtr own = link_->socketFor(id_, endpoint_);
        while (!outbox_.empty()) {
            const std::size_t piece
                = std::min({book_.room(), gateway::kMaxBodyBytes, outbox_.size()});
            if (piece == 0) {
                break;
            }
            const Bytes chunk(outbox_.begin(), outbox_.begin() + static_cast<std::ptrdiff_t>(piece));
            book_.wrote(chunk.data(), chunk.size());
            const Bytes frame = gateway::encode(FrameType::eStreamData, id_, chunk);
            if (own) {
                own->send(std::vector<unsigned char>(frame.begin(), frame.end()));
            } else {
                link_->send(frame);
            }
            outbox_.erase(outbox_.begin(), outbox_.begin() + static_cast<std::ptrdiff_t>(piece));
        }
        if (outbox_.empty() && endWhenDrained_) {
            endWhenDrained_ = false;
            ending = true;
            book_.finishSending();
            const Bytes frame = gateway::encode(FrameType::eStreamClose, id_);
            if (own) {
                own->send(std::vector<unsigned char>(frame.begin(), frame.end()));
            } else {
                link_->send(frame);
            }
        }
    }
    if (ending) {
        link_->forget(id_);
    }
}

std::size_t GatewayStream::pendingBytes() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) {
        return 0;
    }
    return outbox_.size() + book_.pending();
}

void GatewayStream::creditedBy(const std::uint64_t total)
{
    book_.peerCredited(total);
    drain();
}

void GatewayStream::close()
{
    bool tell = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        tell = !closed_;
        closed_ = true;
        endWhenDrained_ = tell;
    }
    if (tell) {
        drain();
    }
    arrived_.notify_all();
}

GatewayEndpoint::GatewayEndpoint(std::shared_ptr<Link> link, const std::uint32_t id,
    std::string host, const bool raw, const bool published, std::string label, std::string owner)
    : link_(std::move(link))
    , id_(id)
    , host_(std::move(host))
    , raw_(raw)
    , published_(published)
    , label_(std::move(label))
    , owner_(std::move(owner))
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
    mustCarryStreams();
    if (stopped_.load()) {
        return nullptr;
    }
    const std::uint32_t id = link_->nextId();
    auto stream = std::make_unique<GatewayStream>(link_, id, id_);
    const Bytes ask = gateway::encodeJson(FrameType::eStreamOpen, id,
        {{"endpoint", id_}, {"host", host}, {"deadline", timeout.count()}});
    const Frame answer = link_->call(ask, id, timeout + kCallTimeout);
    if (answer.type != FrameType::eStreamOpened) {
        return nullptr;
    }
    return stream;
}

std::unique_ptr<StreamBackend> GatewayEndpoint::accept(
    std::string& peerBase64, const std::chrono::seconds timeout)
{
    mustCarryStreams();
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
    if (!raw_) {
        notWithAGateway("a datagram on a destination that carries streams");
    }
    if (stopped_.load()) {
        return;
    }
    if (size > gateway::rawPayloadRoom(host)) {
        return;
    }
    const Bytes frame = gateway::encodeRawSend(id_, host, data, size);
    const http::SocketPtr out = link_->socketFor(id_);
    if (out) {
        out->send(frame);
    }
}

std::vector<std::uint8_t> GatewayEndpoint::receiveRawDatagram(
    const std::chrono::milliseconds timeout)
{
    if (!raw_) {
        notWithAGateway("a datagram on a destination that carries streams");
    }
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
    link_->send(gateway::encode(FrameType::eEndpointStop, id_));
    link_->endStreamsOf(id_);
    link_->forget(id_);
    arrived_.notify_all();
}

void GatewayEndpoint::lost()
{
    if (stopped_.exchange(true)) {
        return;
    }
    ready_.store(false);
    link_->endStreamsOf(id_);
    link_->forget(id_);
    arrived_.notify_all();
    bazarish::log::warn("i2p: the gateway has lost the destination for {}", label());
}

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
    const std::lock_guard<std::mutex> lock(link_->mutex);
    if (!link_->cookie.empty()) {
        dial.headers[gateway::kSessionHeader] = link_->cookie;
    }
    return dial;
}

void GatewayRouter::start()
{
    if (live_.load()) {
        return;
    }
    openControl();
    live_.store(true);
    cover_ = std::thread([this]() { coverLoop(); });
}

void GatewayRouter::stop()
{
    if (live_.exchange(false) && cover_.joinable()) {
        cover_.join();
    }
    std::vector<std::shared_ptr<GatewayEndpoint>> standing;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        for (const auto& [id, endpoint] : link_->endpoints) {
            (void)id;
            if (std::shared_ptr<GatewayEndpoint> mine = endpoint.lock()) {
                standing.push_back(std::move(mine));
            }
        }
    }
    for (const std::shared_ptr<GatewayEndpoint>& endpoint : standing) {
        endpoint->stop();
    }
    {
        http::SocketPtr saying;
        {
            const std::lock_guard<std::mutex> lock(link_->mutex);
            saying = link_->control;
        }
        const auto until = std::chrono::steady_clock::now() + kFarewellWait;
        while (saying && saying->pending() > 0
            && std::chrono::steady_clock::now() < until) {
            std::this_thread::sleep_for(kFarewellPoll);
        }
    }
    http::SocketPtr socket;
    std::vector<http::SocketPtr> flows;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        socket = link_->control;
        link_->control.reset();
        for (const auto& [flow, held] : link_->flows) {
            (void)flow;
            flows.push_back(held);
        }
        link_->flows.clear();
        link_->orphaned.clear();
        link_->waiting.clear();
        link_->cookie.clear();
    }
    for (const http::SocketPtr& held : flows) {
        held->close();
    }
    if (socket) {
        socket->close();
    }
}

bool GatewayRouter::ready() const
{
    return live_.load() && !openFailing_.load();
}

void GatewayRouter::openControl()
{
    const http::SocketDialResult opened = http::openSocket(
        dialFor(),
        [this](const http::SocketPtr& socket, const std::vector<unsigned char>& message) {
            arrived(socket, message);
        },
        [this](const http::SocketPtr& gone) {
            const std::lock_guard<std::mutex> lock(link_->mutex);
            if (link_->control == gone) {
                link_->control.reset();
                aloneSince_.store(millisNow());
            }
        });
    if (opened.socket == nullptr) {
        throw std::runtime_error("bazarish::i2p: the gateway would not open: " + opened.error);
    }

    const std::uint32_t id = link_->nextId();
    const std::shared_ptr<Pending> pending = std::make_shared<Pending>();
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->awaited[id] = pending;
    }
    const Bytes hello
        = gateway::encodeJson(FrameType::eHello, id, {{"version", gateway::kProtocolVersion}});
    opened.socket->send(std::vector<unsigned char>(hello.begin(), hello.end()));

    Frame answer;
    bool said = false;
    {
        std::unique_lock<std::mutex> lock(pending->mutex);
        said = pending->answered.wait_for(lock, kCallTimeout, [&]() { return pending->done; });
        answer = pending->answer;
    }
    {
        const std::lock_guard<std::mutex> held(link_->mutex);
        link_->awaited.erase(id);
    }
    if (!said || answer.type != FrameType::eReady) {
        opened.socket->close();
        throw std::runtime_error("bazarish::i2p: the gateway would not say hello");
    }

    const nlohmann::json body = gateway::bodyJson(answer);
    const bool resumed = body.value("resumed", false);

    nlohmann::json ours = nlohmann::json::array();
    std::vector<Bytes> replay;
    std::vector<Bytes> credits;
    std::vector<std::shared_ptr<GatewayEndpoint>> gone;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->cookie = body.value("session", std::string());
        link_->holding = true;
        for (auto at = link_->waiting.begin(); at != link_->waiting.end();) {
            const bool isData = !at->empty()
                && static_cast<FrameType>(at->front()) == FrameType::eStreamData;
            at = isData ? link_->waiting.erase(at) : std::next(at);
        }
        std::map<std::uint32_t, std::uint64_t> alive;
        if (const auto found = body.find("streams"); found != body.end() && found->is_array()) {
            for (const nlohmann::json& one : *found) {
                alive[one.value("id", 0U)] = one.value("received", std::uint64_t{0});
            }
        }
        for (const auto& [streamId, stream] : link_->streams) {
            const auto found = alive.find(streamId);
            if (found == alive.end()) {
                stream->reset();
                continue;
            }
            ours.push_back({{"id", streamId}, {"received", stream->received()}});
            credits.push_back(gateway::encodeCredit(streamId, stream->consumed()));
            for (Bytes& frame : stream->replayFrames(found->second)) {
                replay.push_back(std::move(frame));
            }
        }
        std::set<std::uint32_t> standing;
        if (const auto found = body.find("endpoints"); found != body.end() && found->is_array()) {
            for (const nlohmann::json& one : *found) {
                const std::uint32_t endpointId = one.value("id", 0U);
                standing.insert(endpointId);
                const auto at = link_->endpoints.find(endpointId);
                if (at == link_->endpoints.end()) {
                    continue;
                }
                if (const std::shared_ptr<GatewayEndpoint> endpoint = at->second.lock()) {
                    endpoint->statusChanged(one.value("ready", false), one.value("tunnelsIn", 0),
                        one.value("tunnelsOut", 0), one.value("leaseSets", 0));
                }
            }
        }
        for (const auto& [endpointId, held] : link_->endpoints) {
            if (standing.count(endpointId) == 0) {
                if (std::shared_ptr<GatewayEndpoint> endpoint = held.lock()) {
                    gone.push_back(std::move(endpoint));
                }
            }
        }
    }
    for (const std::shared_ptr<GatewayEndpoint>& endpoint : gone) {
        endpoint->lost();
    }
    if (!ours.empty()) {
        const Bytes resume
            = gateway::encodeJson(FrameType::eResume, link_->nextId(), {{"streams", ours}});
        opened.socket->send(std::vector<unsigned char>(resume.begin(), resume.end()));
    }
    for (const Bytes& frame : replay) {
        opened.socket->send(std::vector<unsigned char>(frame.begin(), frame.end()));
    }
    for (const Bytes& frame : credits) {
        opened.socket->send(std::vector<unsigned char>(frame.begin(), frame.end()));
    }

    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        for (const auto& [ref, request] : link_->awaited) {
            (void)ref;
            const std::lock_guard<std::mutex> waiting(request->mutex);
            if (!request->done && !request->request.empty()) {
                opened.socket->send(std::vector<unsigned char>(
                    request->request.begin(), request->request.end()));
            }
        }
        for (const Bytes& frame : link_->waiting) {
            opened.socket->send(std::vector<unsigned char>(frame.begin(), frame.end()));
        }
        link_->waiting.clear();
        link_->control = opened.socket;
        link_->holding = false;
        link_->lastUse.store(millisNow());
    }
    bazarish::log::info("i2p: a gateway running i2pd {}, {}",
        body.value("i2pd", std::string("?")), resumed ? "session rejoined" : "new session");
}

void GatewayRouter::closeControl()
{
    http::SocketPtr socket;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        socket = link_->control;
        link_->control.reset();
    }
    if (socket) {
        aloneSince_.store(millisNow());
        socket->close();
    }
}

void GatewayRouter::abandon()
{
    std::vector<GatewayStream*> stranded;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        if (link_->waiting.empty() && link_->streams.empty()) {
            return;
        }
        link_->waiting.clear();
        for (const auto& [id, stream] : link_->streams) {
            (void)id;
            stranded.push_back(stream);
        }
        for (GatewayStream* const stream : stranded) {
            stream->reset();
        }
    }
    bazarish::log::warn(
        "i2p: the gateway has been out of reach longer than a session lasts; "
        "{} stream(s) given up",
        stranded.size());
}

bool GatewayRouter::hasControl() const
{
    const std::lock_guard<std::mutex> lock(link_->mutex);
    return link_->control != nullptr && link_->control->open();
}

bool GatewayRouter::quiet() const
{
    const std::lock_guard<std::mutex> lock(link_->mutex);
    if (!link_->awaited.empty()) {
        return false;
    }
    return millisNow() - link_->lastUse.load() >= kQuietBeforeChurn.count();
}

void GatewayRouter::decoy()
{
    const Bytes noise = randomBytes(static_cast<std::size_t>(
        drawBetween(gateway::kDecoyRequestMinBytes, gateway::kDecoyRequestMaxBytes)));
    (void)http::probeHost(dialFor(), std::string(noise.begin(), noise.end()));
}

void GatewayRouter::coverLoop()
{
    const auto chosen = [](const std::chrono::milliseconds set,
                            const std::chrono::milliseconds fallback) {
        return set.count() > 0 ? set : fallback;
    };
    const std::chrono::milliseconds decoyMin
        = chosen(config_.gatewayDecoyMin, gateway::kDecoyMinDelay);
    const std::chrono::milliseconds decoyMax
        = chosen(config_.gatewayDecoyMax, gateway::kDecoyMaxDelay);
    const std::chrono::milliseconds minLife = chosen(config_.gatewayControlMinLife,
        std::chrono::milliseconds(gateway::kControlSocketMinLife));
    const std::chrono::milliseconds maxLife = chosen(config_.gatewayControlMaxLife,
        std::chrono::milliseconds(gateway::kControlSocketMaxLife));
    const std::chrono::milliseconds maxGap = chosen(
        config_.gatewayControlMaxGap, std::chrono::milliseconds(gateway::kControlGapMax));

    const auto nextDecoy = [decoyMin, decoyMax]() {
        return std::chrono::steady_clock::now() + drawBetween(decoyMin, decoyMax);
    };
    const auto nextChurn = [minLife, maxLife]() {
        return std::chrono::steady_clock::now() + drawBetween(minLife, maxLife);
    };
    auto decoyAt = nextDecoy();
    auto churnAt = nextChurn();
    auto openAt = std::chrono::steady_clock::now();
    std::chrono::milliseconds backoff = kFirstRetry;

    while (live_.load()) {
        std::this_thread::sleep_for(kCoverTick);
        if (!live_.load()) {
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        reattachOrphans();

        if (!hasControl()) {
            if (now < openAt) {
                continue;
            }
            try {
                openControl();
                openFailing_.store(false);
                backoff = kFirstRetry;
                churnAt = nextChurn();
            } catch (const std::exception& error) {
                openFailing_.store(true);
                bazarish::log::warn(
                    "i2p: the gateway would not take a socket: {}", error.what());
                openAt = std::chrono::steady_clock::now() + backoff;
                backoff = std::min(backoff * 2, kSlowestRetry);
                if (millisNow() - aloneSince_.load()
                    > std::chrono::milliseconds(gateway::kSessionTtl).count()) {
                    abandon();
                }
            }
            continue;
        }

        if (now >= decoyAt) {
            decoy();
            decoyAt = nextDecoy();
        }
        if (!live_.load() || now < churnAt) {
            continue;
        }
        if (!quiet()) {
            continue;
        }
        closeControl();
        openAt = std::chrono::steady_clock::now()
            + drawBetween(std::min(std::chrono::milliseconds(gateway::kControlGapMin), maxGap),
                maxGap);
    }
}

void Link::send(const Bytes& frame)
{
    http::SocketPtr socket;
    {
        const std::lock_guard<std::mutex> lock(mutex);
        if (control == nullptr) {
            if (holding || (!frame.empty()
                && static_cast<FrameType>(frame.front()) != FrameType::eStreamData)) {
                waiting.push_back(frame);
            }
            return;
        }
        socket = control;
        lastUse.store(millisNow());
    }
    socket->send(std::vector<unsigned char>(frame.begin(), frame.end()));
}

http::SocketPtr Link::socketFor(const std::uint32_t flow) const
{
    const std::lock_guard<std::mutex> lock(mutex);
    const auto found = flows.find(flow);
    return found == flows.end() ? nullptr : found->second;
}

http::SocketPtr Link::socketFor(
    const std::uint32_t stream, const std::uint32_t endpoint) const
{
    const http::SocketPtr own = socketFor(stream);
    return own ? own : socketFor(endpoint);
}

bool GatewayRouter::attach(const std::uint32_t flow, const std::uint64_t received)
{
    if (flow == 0) {
        return false;
    }
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        if (link_->flows.count(flow) > 0
            || link_->flows.size() + kControlSocketsKept >= gateway::kMaxSocketsPerSession) {
            return false;
        }
    }
    const http::SocketDialResult opened = http::openSocket(
        dialFor(),
        [this](const http::SocketPtr& socket, const std::vector<unsigned char>& message) {
            arrived(socket, message);
        },
        [this, flow](const http::SocketPtr&) {
            const std::lock_guard<std::mutex> lock(link_->mutex);
            link_->flows.erase(flow);
            link_->orphaned.insert(flow);
        });
    if (opened.socket == nullptr) {
        bazarish::log::debug("i2p: no socket of its own for flow {}: {}", flow, opened.error);
        return false;
    }
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->flows[flow] = opened.socket;
    }
    opened.socket->send(gateway::encodeJson(FrameType::eAttach, flow, {{"received", received}}));
    return true;
}

void GatewayRouter::reattachOrphans()
{
    std::vector<std::pair<std::uint32_t, std::uint64_t>> again;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        for (auto at = link_->orphaned.begin(); at != link_->orphaned.end();) {
            const auto stream = link_->streams.find(*at);
            if (stream != link_->streams.end()) {
                if (stream->second->givenUp()) {
                    at = link_->orphaned.erase(at);
                    continue;
                }
                again.emplace_back(*at, stream->second->received());
                ++at;
                continue;
            }
            const auto endpoint = link_->endpoints.find(*at);
            if (endpoint == link_->endpoints.end() || endpoint->second.expired()) {
                at = link_->orphaned.erase(at);
                continue;
            }
            again.emplace_back(*at, 0);
            ++at;
        }
    }
    for (const auto& [flow, received] : again) {
        if (attach(flow, received)) {
            const std::lock_guard<std::mutex> lock(link_->mutex);
            link_->orphaned.erase(flow);
        }
    }
}

Frame Link::call(
    const Bytes& frame, const std::uint32_t ref, const std::chrono::seconds timeout)
{
    const std::shared_ptr<Pending> pending = std::make_shared<Pending>();
    pending->request = frame;
    bool live = false;
    {
        const std::lock_guard<std::mutex> lock(mutex);
        awaited[ref] = pending;
        live = control != nullptr && control->open();
    }
    send(frame);

    std::unique_lock<std::mutex> lock(pending->mutex);
    const bool answered = pending->answered.wait_for(lock, timeout, [&]() {
        return pending->done;
    });
    Frame answer = pending->answer;
    lock.unlock();
    {
        const std::lock_guard<std::mutex> held(mutex);
        awaited.erase(ref);
    }
    if (!answered) {
        bazarish::log::warn("i2p: the gateway left {} #{} unanswered for {} s, sent {}",
            gateway::frameTypeName(static_cast<FrameType>(frame.front())), ref, timeout.count(),
            live ? "on a live socket" : "while no socket was open");
        throw std::runtime_error("bazarish::i2p: the gateway did not answer in time");
    }
    return answer;
}

void Link::remember(const std::uint32_t id, GatewayStream* const stream)
{
    const std::lock_guard<std::mutex> lock(mutex);
    if (stream == nullptr) {
        streams.erase(id);
        return;
    }
    streams[id] = stream;
}

void Link::endStreamsOf(const std::uint32_t endpoint)
{
    const std::lock_guard<std::mutex> lock(mutex);
    for (const auto& [id, stream] : streams) {
        (void)id;
        if (stream->endpoint() == endpoint) {
            stream->reset();
        }
    }
}

void Link::forget(const std::uint32_t id)
{
    http::SocketPtr flow;
    {
        const std::lock_guard<std::mutex> lock(mutex);
        streams.erase(id);
        endpoints.erase(id);
        const auto found = flows.find(id);
        if (found != flows.end()) {
            flow = found->second;
            flows.erase(found);
        }
    }
    if (flow) {
        flow->close();
    }
}

std::shared_ptr<EndpointBackend> GatewayRouter::createEndpoint(const EndpointConfig& config)
{
    if (config.keys.has_value()) {
        notWithAGateway("a destination built from a key of your own");
    }
    const std::uint32_t id = link_->nextId();
    const bool raw = config.traffic == Traffic::eRaw;
    const nlohmann::json ask = {{"kind", raw ? "raw" : "stream"},
        {"privacy", privacyName(config.privacy)}, {"tunnels", config.tunnelQuantity},
        {"published", config.published}, {"realtime", config.realtime}};
    const Frame answer
        = link_->call(gateway::encodeJson(FrameType::eEndpointCreate, id, ask), id,
            kCallTimeout);
    if (answer.type != FrameType::eOk) {
        throw std::runtime_error("bazarish::i2p: the gateway refused a destination");
    }
    const std::string host = gateway::bodyJson(answer).value("host", std::string());
    if (host.empty()) {
        throw std::runtime_error("bazarish::i2p: the gateway named no address");
    }
    const auto endpoint = std::make_shared<GatewayEndpoint>(
        link_, id, host, raw, config.published, config.label, config.owner);
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->endpoints[id] = endpoint;
    }
    if (raw || config.bulk) {
        if (!attach(id, 0)) {
            const std::lock_guard<std::mutex> lock(link_->mutex);
            link_->orphaned.insert(id);
        }
    }
    return endpoint;
}

void GatewayRouter::retagEndpoint(
    const EndpointBackend& endpoint, std::string label, std::string owner)
{
    const std::lock_guard<std::mutex> lock(link_->mutex);
    for (const auto& [id, held] : link_->endpoints) {
        (void)id;
        const std::shared_ptr<GatewayEndpoint> mine = held.lock();
        if (mine != nullptr && mine.get() == &endpoint) {
            mine->retag(std::move(label), std::move(owner));
            return;
        }
    }
}

std::vector<LocalDestination> GatewayRouter::localDestinations() const
{
    std::vector<LocalDestination> destinations;
    const std::lock_guard<std::mutex> lock(link_->mutex);
    for (const auto& [id, held] : link_->endpoints) {
        (void)id;
        const std::shared_ptr<GatewayEndpoint> endpoint = held.lock();
        if (endpoint == nullptr) {
            continue;
        }
        LocalDestination entry;
        entry.label = endpoint->label();
        entry.owner = endpoint->owner();
        entry.host = endpoint->routingHost();
        entry.published = endpoint->published();
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
    std::shared_ptr<Pending> waiting;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        const auto found = link_->awaited.find(frame.ref);
        if (found != link_->awaited.end()) {
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

    std::shared_ptr<GatewayEndpoint> endpoint;
    GatewayStream* stream = nullptr;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        const auto atEndpoint = link_->endpoints.find(frame.ref);
        if (atEndpoint != link_->endpoints.end()) {
            endpoint = atEndpoint->second.lock();
        }
        const auto atStream = link_->streams.find(frame.ref);
        if (atStream != link_->streams.end()) {
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
                const std::lock_guard<std::mutex> lock(link_->mutex);
                const auto found = link_->endpoints.find(body.value("endpoint", 0U));
                if (found != link_->endpoints.end()) {
                    on = found->second.lock();
                }
            }
            if (on == nullptr) {
                return;
            }
            on->callerArrived(
                std::make_unique<GatewayStream>(link_, frame.ref, body.value("endpoint", 0U)),
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
