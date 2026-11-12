// Bazarish project (c) 2026
#include "I2pBackend.hpp"

#include "bazarish/GatewayChannel.hpp"
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
#include <optional>
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
// A delegation runs to the end of today; a renewal also covers the next day.
constexpr int kFirstDelegationDays = 1;
constexpr int kRenewedDelegationDays = 2;
constexpr std::chrono::milliseconds kCoverTick{200};
constexpr std::size_t kControlSocketsKept = 2;
constexpr std::chrono::milliseconds kQuietBeforeChurn{1000};
constexpr std::chrono::milliseconds kFirstRetry{500};
constexpr std::chrono::milliseconds kSlowestRetry{15000};
constexpr std::chrono::milliseconds kFarewellWait{2000};
constexpr std::chrono::milliseconds kFarewellPoll{20};

bool answers(const FrameType type)
{
    return type == FrameType::eOk || type == FrameType::eError || type == FrameType::eReady
        || type == FrameType::eStreamOpened;
}

std::int64_t millisNow()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::chrono::milliseconds drawBetween(
    const std::chrono::milliseconds low, const std::chrono::milliseconds high)
{
    return std::chrono::milliseconds(static_cast<std::int64_t>(
        randomBetween(static_cast<std::uint64_t>(low.count()),
            static_cast<std::uint64_t>(high.count()))));
}

// A steady max() deadline overflows where libstdc++ waits on the system clock (musl).
template <class Wakes>
bool waitWithin(std::condition_variable& signal, std::unique_lock<std::mutex>& lock,
    const std::chrono::seconds timeout, Wakes wakes)
{
    if (timeout.count() <= 0) {
        signal.wait(lock, wakes);
        return true;
    }
    return signal.wait_for(lock, timeout, wakes);
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

class StreamState;
class GatewayEndpoint;

class Link {
public:
    explicit Link(const bool odd) : ids_(odd) {}

    std::uint32_t nextId() { return ids_.next(); }
    void send(const Bytes& frame);
    http::SocketPtr socketFor(std::uint32_t flow) const;
    std::optional<Frame> call(const Bytes& frame, std::uint32_t ref, std::chrono::seconds timeout);
    std::shared_ptr<Pending> expect(const Bytes& frame, std::uint32_t ref);
    std::optional<Frame> await(
        const std::shared_ptr<Pending>& pending, std::uint32_t ref, std::chrono::seconds timeout);
    void forget(std::uint32_t id);
    void remember(std::uint32_t id, const std::shared_ptr<StreamState>& stream);
    void release(std::uint32_t id);
    void endStreamsOf(std::uint32_t endpoint);
    void abandonCalls();

    mutable std::mutex mutex;
    gateway::Ids ids_;
    http::SocketPtr control;
    Bytes sessionKey;
    std::deque<Bytes> tickets;
    std::map<std::uint32_t, std::shared_ptr<Pending>> awaited;
    std::map<std::uint32_t, std::weak_ptr<GatewayEndpoint>> endpoints;
    // A status may arrive before the create's answer.
    std::map<std::uint32_t, std::optional<Frame>> creating;
    std::map<std::uint32_t, std::weak_ptr<StreamState>> streams;
    // Frames reach the streams one at a time, whichever socket they came on.
    std::mutex delivering;
    std::map<std::uint32_t, http::SocketPtr> flows;
    std::set<std::uint32_t> orphaned;
    std::deque<Bytes> waiting;
    bool holding = false;
    std::atomic<std::int64_t> lastUse{0};
    std::atomic<std::int64_t> lastArrival{0};
    std::atomic<std::int64_t> aloneSince{0};

    std::string describe() const
    {
        const std::lock_guard<std::mutex> lock(mutex);
        return std::string("control ") + (control && control->open() ? "open" : "closed")
            + ", last frame " + std::to_string(millisNow() - lastArrival.load()) + " ms ago, "
            + std::to_string(streams.size()) + " stream(s), " + std::to_string(flows.size())
            + " flow socket(s), " + std::to_string(awaited.size()) + " call(s) waiting, "
            + std::to_string(waiting.size()) + " frame(s) held";
    }
};

class GatewayRouter;

class StreamState {
public:
    StreamState(std::shared_ptr<Link> link, std::uint32_t id, std::uint32_t endpoint);

    void setReadTimeout(std::chrono::seconds timeout) { readTimeout_ = timeout; }
    std::size_t readSome(ByteBuffer buffer);
    void writeAll(ByteView data);
    std::size_t pendingBytes() const;
    void close();

    std::uint32_t id() const { return id_; }
    std::uint32_t endpoint() const { return endpoint_; }
    void arrived(const Bytes& data);
    void creditedBy(std::uint64_t total);
    std::uint64_t received() const { return book_.received(); }
    std::uint64_t consumed() const { return book_.consumedTotal(); }
    std::vector<Bytes> replayFrames(std::uint64_t peerReceived);
    void farSideFinished();
    void reset();

private:
    void drain();

    std::shared_ptr<Link> link_;
    std::uint32_t id_;
    std::uint32_t endpoint_;
    gateway::StreamBook book_;
    std::chrono::seconds readTimeout_{0};
    std::mutex sendMutex_;
    mutable std::mutex mutex_;
    std::condition_variable arrived_;
    std::deque<unsigned char> inbox_;
    std::deque<unsigned char> outbox_;
    bool finished_ = false;
    bool closed_ = false;
    bool endWhenDrained_ = false;
};

class GatewayStream final : public StreamBackend {
public:
    GatewayStream(const std::shared_ptr<Link>& link, std::uint32_t id, std::uint32_t endpoint);
    ~GatewayStream() override;

    void setReadTimeout(const std::chrono::seconds timeout) override
    {
        state_->setReadTimeout(timeout);
    }
    std::size_t readSome(const ByteBuffer buffer) override { return state_->readSome(buffer); }
    void writeAll(const ByteView data) override { state_->writeAll(data); }
    std::size_t pendingBytes() const override { return state_->pendingBytes(); }
    void close() override { state_->close(); }
    void reset() { state_->reset(); }

private:
    const std::shared_ptr<Link> link_;
    const std::shared_ptr<StreamState> state_;
};

class GatewayEndpoint : public EndpointBackend {
public:
    GatewayEndpoint(std::shared_ptr<Link> link, std::uint32_t id, std::string host, bool raw,
        bool published, std::string label, std::string accountLabel, std::string target,
        std::optional<Keys> master);
    ~GatewayEndpoint() override;

    bool ready() const override { return ready_.load(); }
    bool lost() const override { return stopped_.load(); }
    std::string publicBase64() const override
    {
        notWithAGateway("the base64 of a destination the gateway minted");
    }
    std::string routingHost() const override { return host_; }
    void refreshOfflineSignature(const Keys&) override
    {
        notWithAGateway("swapping an offline transient");
    }
    void setLeaseSetReaderKey(const Bytes&) override
    {
        notWithAGateway("a lease-set reader key after the destination is made");
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

    void sendDatagram(const std::string&, ByteView) override
    {
        notWithAGateway("a repliable datagram");
    }
    Datagram receiveDatagram(std::chrono::milliseconds) override
    {
        notWithAGateway("a repliable datagram");
    }
    void sendRawDatagram(const std::string& host, ByteView data) override;
    std::vector<std::uint8_t> receiveRawDatagram(std::chrono::milliseconds timeout) override;

    void stop() override;
    void lost();
    void renewDelegation();

    std::uint32_t id() const { return id_; }
    bool raw() const { return raw_; }
    bool published() const { return published_; }
    std::string label() const { return tag_.label(); }
    std::string accountLabel() const { return tag_.accountLabel(); }
    void retag(std::string label, std::string accountLabel)
    {
        tag_.retag(std::move(label), std::move(accountLabel));
    }
    void statusChanged(bool ready, int in, int out, int leases, bool localRoute);
    void datagramArrived(std::vector<std::uint8_t> payload);
    void callerArrived(std::unique_ptr<GatewayStream> stream, const std::string& peer);
    int inboundTunnels() const { return in_.load(); }
    int outboundTunnels() const { return out_.load(); }
    int leaseSets() const { return leases_.load(); }
    bool localRoute() const { return localRoute_.load(); }

private:
    std::shared_ptr<Link> link_;
    std::uint32_t id_;
    std::string host_;
    bool raw_;
    bool published_;
    DestTag tag_;
    std::string target_;
    const std::optional<Keys> master_;
    std::atomic<bool> ready_{false};
    std::atomic<bool> stopped_{false};
    std::atomic<int> in_{0};
    std::atomic<int> out_{0};
    std::atomic<int> leases_{0};
    std::atomic<bool> localRoute_{false};
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
        what.warmPool = true;
        what.leaseSetRefresh = true;
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
    std::optional<DestinationDetail> destinationDetail(const std::string&) const override
    {
        notWithAGateway("a destination's tunnels and lease sets");
    }
    LeaseSetRefresh refreshLeaseSet(
        const std::string& localHost, const std::string& remoteHost) override;

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

    void repointGateway(const GatewayTarget& target) override;

    std::shared_ptr<EndpointBackend> createEndpoint(const EndpointConfig& config) override;
    void retagEndpoint(
        const EndpointBackend& endpoint, std::string label, std::string accountLabel) override;

    bool attach(std::uint32_t flow);
    void reattachOrphans();

private:
    void arrived(const http::SocketPtr& socket, const std::vector<unsigned char>& message);
    void dispatch(const Frame& frame);
    void deliver(const Frame& frame);
    std::vector<std::shared_ptr<GatewayEndpoint>> endpointsHeld() const;
    http::SocketDial dialFor() const;
    http::SocketDial dialLocked() const;
    gateway::ChannelOpened openChannelSocket(
        gateway::ChannelMessageFn onMessage, gateway::ChannelClosedFn onClosed);
    void openControl();
    void closeControl();
    void coverLoop();
    void decoy();
    bool quiet() const;
    bool hasControl() const;
    void abandon();

    RouterConfig config_;
    // Guards the gateway half of config_ and the generation that counts its changes.
    mutable std::mutex targetMutex_;
    std::uint64_t targetGeneration_ = 0;
    std::shared_ptr<Link> link_;
    std::thread cover_;
    std::atomic<bool> live_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<bool> openFailing_{false};
};

StreamState::StreamState(
    std::shared_ptr<Link> link, const std::uint32_t id, const std::uint32_t endpoint)
    : link_(std::move(link))
    , id_(id)
    , endpoint_(endpoint)
{
}

GatewayStream::GatewayStream(
    const std::shared_ptr<Link>& link, const std::uint32_t id, const std::uint32_t endpoint)
    : link_(link)
    , state_(std::make_shared<StreamState>(link, id, endpoint))
{
    link_->remember(id, state_);
}

GatewayStream::~GatewayStream()
{
    state_->close();
    link_->release(state_->id());
}

void StreamState::arrived(const Bytes& data)
{
    book_.tookIn(data.size());
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        inbox_.insert(inbox_.end(), data.begin(), data.end());
    }
    arrived_.notify_all();
}

void StreamState::farSideFinished()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        finished_ = true;
    }
    arrived_.notify_all();
}

void StreamState::reset()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        finished_ = true;
        closed_ = true;
        outbox_.clear();
    }
    arrived_.notify_all();
}

std::size_t StreamState::readSome(const ByteBuffer buffer)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (!waitWithin(arrived_, lock, readTimeout_,
            [this]() { return !inbox_.empty() || finished_ || closed_; })) {
        lock.unlock();
        bazarish::log::warn("i2p: gateway stream #{} silent; {}", id_, link_->describe());
        throw std::runtime_error("bazarish::i2p: the stream said nothing in time");
    }
    if (inbox_.empty()) {
        return 0;
    }
    const std::size_t got = std::min(buffer.size(), inbox_.size());
    std::copy(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(got), buffer.begin());
    inbox_.erase(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(got));
    lock.unlock();

    book_.consumed(got);
    const Bytes credit = gateway::encodeCredit(id_, book_.consumedTotal());
    if (const http::SocketPtr own = link_->socketFor(endpoint_)) {
        own->send(std::vector<unsigned char>(credit.begin(), credit.end()));
    } else {
        link_->send(credit);
    }
    return got;
}

void StreamState::writeAll(const ByteView data)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) {
            throw std::runtime_error("bazarish::i2p: the stream is closed");
        }
        outbox_.insert(outbox_.end(), data.begin(), data.end());
    }
    drain();
}

std::vector<Bytes> StreamState::replayFrames(const std::uint64_t peerReceived)
{
    const Bytes again = book_.replay(peerReceived);
    std::vector<Bytes> frames;
    for (std::size_t at = 0; at < again.size(); at += gateway::kMaxBodyBytes) {
        const std::size_t piece = std::min(gateway::kMaxBodyBytes, again.size() - at);
        frames.push_back(gateway::encode(
            FrameType::eStreamData, id_, ByteView(again).subspan(at, piece)));
    }
    return frames;
}

void StreamState::drain()
{
    // The link locks its own mutex and then a stream's, so this one is never held into it.
    const std::lock_guard<std::mutex> sending(sendMutex_);
    std::vector<Bytes> frames;
    bool ending = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        while (!outbox_.empty()) {
            const std::size_t piece
                = std::min({book_.room(), gateway::kMaxBodyBytes, outbox_.size()});
            if (piece == 0) {
                break;
            }
            const Bytes chunk(outbox_.begin(), outbox_.begin() + static_cast<std::ptrdiff_t>(piece));
            book_.wrote(chunk);
            frames.push_back(gateway::encode(FrameType::eStreamData, id_, chunk));
            outbox_.erase(outbox_.begin(), outbox_.begin() + static_cast<std::ptrdiff_t>(piece));
        }
        if (outbox_.empty() && endWhenDrained_) {
            endWhenDrained_ = false;
            ending = true;
            book_.finishSending();
            frames.push_back(gateway::encode(FrameType::eStreamClose, id_));
        }
    }
    const http::SocketPtr own = link_->socketFor(endpoint_);
    for (const Bytes& frame : frames) {
        if (own) {
            own->send(std::vector<unsigned char>(frame.begin(), frame.end()));
        } else {
            link_->send(frame);
        }
    }
    if (ending) {
        link_->forget(id_);
    }
}

std::size_t StreamState::pendingBytes() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) {
        return 0;
    }
    return outbox_.size() + book_.pending();
}

void StreamState::creditedBy(const std::uint64_t total)
{
    book_.peerCredited(total);
    drain();
}

void StreamState::close()
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
    std::string host, const bool raw, const bool published, std::string label,
    std::string accountLabel, std::string target, std::optional<Keys> master)
    : link_(std::move(link))
    , id_(id)
    , host_(std::move(host))
    , raw_(raw)
    , published_(published)
    , tag_(std::move(label), std::move(accountLabel))
    , target_(std::move(target))
    , master_(std::move(master))
{
}

void GatewayEndpoint::renewDelegation()
{
    if (!master_.has_value() || stopped_.load()) {
        return;
    }
    link_->send(gateway::encodeJson(FrameType::eEndpointDelegate, id_,
        {{"keys", master_->issueTransient(kRenewedDelegationDays).privateBase64()}}));
}

GatewayEndpoint::~GatewayEndpoint()
{
    stop();
}

void GatewayEndpoint::statusChanged(
    const bool isReady, const int in, const int out, const int leases, const bool localRoute)
{
    const bool wasReady = ready_.exchange(isReady);
    in_.store(in);
    out_.store(out);
    leases_.store(leases);
    localRoute_.store(localRoute);
    if (isReady && !wasReady && !localRoute && !target_.empty()) {
        bazarish::log::info("i2p: the way to {} goes into I2P: the gateway does not route it",
            bazarish::log::redact(target_));
    }
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
    const std::uint32_t id = link_->nextId();
    const Bytes ask = gateway::encodeJson(FrameType::eStreamOpen, id,
        {{"endpoint", id_}, {"host", host}, {"deadline", timeout.count()}});
    std::unique_ptr<GatewayStream> stream;
    std::shared_ptr<Pending> dial;
    {
        // Under the lock stop() takes, so a stop either comes first or finds this dial.
        const std::lock_guard<std::mutex> lock(mutex_);
        if (stopped_.load()) {
            return nullptr;
        }
        stream = std::make_unique<GatewayStream>(link_, id, id_);
        dial = link_->expect(ask, id);
    }
    link_->send(ask);
    const std::optional<Frame> answer = link_->await(dial, id, timeout + kCallTimeout);
    if (!answer || answer->type != FrameType::eStreamOpened) {
        return nullptr;
    }
    return stream;
}

std::unique_ptr<StreamBackend> GatewayEndpoint::accept(
    std::string& peerBase64, const std::chrono::seconds timeout)
{
    mustCarryStreams();
    std::unique_lock<std::mutex> lock(mutex_);
    (void)waitWithin(
        arrived_, lock, timeout, [this]() { return !callers_.empty() || stopped_.load(); });
    if (callers_.empty()) {
        return nullptr;
    }
    std::unique_ptr<GatewayStream> caller = std::move(callers_.front().first);
    peerBase64 = callers_.front().second;
    callers_.pop_front();
    return caller;
}

void GatewayEndpoint::sendRawDatagram(const std::string& host, const ByteView data)
{
    if (!raw_) {
        notWithAGateway("a datagram on a destination that carries streams");
    }
    if (stopped_.load()) {
        return;
    }
    if (data.size() > gateway::rawPayloadRoom(host)) {
        return;
    }
    const Bytes frame = gateway::encodeRawSend(id_, host, data);
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
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (stopped_.exchange(true)) {
            return;
        }
    }
    link_->send(gateway::encode(FrameType::eEndpointStop, id_));
    link_->endStreamsOf(id_);
    link_->forget(id_);
    arrived_.notify_all();
}

void GatewayEndpoint::lost()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (stopped_.exchange(true)) {
            return;
        }
    }
    ready_.store(false);
    link_->endStreamsOf(id_);
    link_->forget(id_);
    arrived_.notify_all();
    bazarish::log::warn("i2p: the gateway has lost the destination for {}", label());
}

http::SocketDial GatewayRouter::dialFor() const
{
    const std::lock_guard<std::mutex> lock(targetMutex_);
    return dialLocked();
}

http::SocketDial GatewayRouter::dialLocked() const
{
    http::SocketDial dial;
    dial.host = config_.gatewayHost;
    dial.port = config_.gatewayPort;
    dial.path = config_.gatewayPath;
    dial.tls = config_.gatewayTls;
    dial.maxMessageBytes = gateway::kMaxRecordBytes;
    dial.idleTimeout = gateway::kKeepalive + gateway::kPongTimeout;
    return dial;
}

gateway::ChannelOpened GatewayRouter::openChannelSocket(
    gateway::ChannelMessageFn onMessage, gateway::ChannelClosedFn onClosed)
{
    std::optional<gateway::ChannelJoin> join;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        if (!link_->sessionKey.empty() && !link_->tickets.empty()) {
            join = gateway::ChannelJoin{link_->sessionKey, link_->tickets.front()};
            link_->tickets.pop_front();
        }
    }
    http::SocketDial dial;
    std::string fingerprint;
    std::uint64_t generation = 0;
    {
        const std::lock_guard<std::mutex> lock(targetMutex_);
        dial = dialLocked();
        fingerprint = config_.gatewayFingerprint;
        generation = targetGeneration_;
    }
    gateway::ChannelOpened opened = gateway::openChannel(
        dial, fingerprint, join, std::move(onMessage), std::move(onClosed));
    {
        const std::lock_guard<std::mutex> lock(targetMutex_);
        if (generation != targetGeneration_) {
            if (opened.socket != nullptr) {
                opened.socket->close();
            }
            gateway::ChannelOpened stale;
            stale.error = "the gateway changed while this socket opened";
            return stale;
        }
    }
    const std::lock_guard<std::mutex> lock(link_->mutex);
    if (opened.welcome.has_value()) {
        link_->sessionKey = opened.welcome->sessionKey;
        link_->tickets.assign(opened.welcome->tickets.begin(), opened.welcome->tickets.end());
    } else if (join.has_value() && !opened.ticketSpent && link_->sessionKey == join->sessionKey) {
        link_->tickets.push_front(join->ticket);
    }
    return opened;
}

void GatewayRouter::repointGateway(const GatewayTarget& target)
{
    {
        const std::lock_guard<std::mutex> lock(targetMutex_);
        config_.gatewayHost = target.host;
        config_.gatewayPort = target.port;
        config_.gatewayPath = target.path;
        config_.gatewayFingerprint = target.fingerprint;
        config_.gatewayTls = target.tls;
        ++targetGeneration_;
    }
    std::vector<http::SocketPtr> flows;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->sessionKey.clear();
        link_->tickets.clear();
        for (const auto& [flow, socket] : link_->flows) {
            (void)flow;
            flows.push_back(socket);
        }
    }
    for (const http::SocketPtr& socket : flows) {
        socket->close();
    }
    closeControl();
    bazarish::log::info("i2p: the gateway is now {}", target.host);
}

void GatewayRouter::start()
{
    if (live_.load()) {
        return;
    }
    stopping_.store(false);
    openControl();
    live_.store(true);
    cover_ = std::thread([this]() { coverLoop(); });
}

void GatewayRouter::stop()
{
    stopping_.store(true);
    if (live_.exchange(false) && cover_.joinable()) {
        link_->abandonCalls();
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
        link_->sessionKey.clear();
        link_->tickets.clear();
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
    const gateway::ChannelOpened opened = openChannelSocket(
        [this](const http::SocketPtr& socket, const std::vector<unsigned char>& message) {
            arrived(socket, message);
        },
        [link = link_](const http::SocketPtr& gone) {
            const std::lock_guard<std::mutex> lock(link->mutex);
            if (link->control == gone) {
                link->control.reset();
                link->aloneSince.store(millisNow());
            }
        });
    if (opened.socket == nullptr) {
        if (opened.wrongGateway) {
            throw WrongGateway("bazarish::i2p: " + opened.error);
        }
        throw std::runtime_error("bazarish::i2p: the gateway would not open: " + opened.error);
    }

    const std::uint32_t id = link_->nextId();
    const std::shared_ptr<Pending> pending = std::make_shared<Pending>();
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->awaited[id] = pending;
    }
    // stop() says so before it abandons the calls: one made after that sees it here.
    if (stopping_.load()) {
        {
            const std::lock_guard<std::mutex> lock(link_->mutex);
            link_->awaited.erase(id);
        }
        opened.socket->close();
        throw std::runtime_error("bazarish::i2p: the router is stopping");
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
    // Released only after the link's mutex is.
    std::vector<std::shared_ptr<GatewayEndpoint>> told;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
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
        for (const auto& [streamId, held] : link_->streams) {
            const std::shared_ptr<StreamState> stream = held.lock();
            if (stream == nullptr) {
                continue;
            }
            const auto found = alive.find(streamId);
            if (found == alive.end()) {
                // Still being opened: the open goes again below, so the gateway has not lost it.
                if (link_->awaited.count(streamId) == 0) {
                    stream->reset();
                }
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
                if (std::shared_ptr<GatewayEndpoint> endpoint = at->second.lock()) {
                    endpoint->statusChanged(one.value("ready", false), one.value("tunnelsIn", 0),
                        one.value("tunnelsOut", 0), one.value("leaseSets", 0),
                        one.value("localRoute", false));
                    told.push_back(std::move(endpoint));
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
        link_->aloneSince.store(millisNow());
        socket->close();
    }
}

void GatewayRouter::abandon()
{
    std::vector<std::shared_ptr<StreamState>> stranded;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        if (link_->waiting.empty() && link_->streams.empty()) {
            return;
        }
        link_->waiting.clear();
        for (const auto& [id, held] : link_->streams) {
            (void)id;
            if (std::shared_ptr<StreamState> stream = held.lock()) {
                stranded.push_back(std::move(stream));
            }
        }
        for (const std::shared_ptr<StreamState>& stream : stranded) {
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
        randomBetween(gateway::kDecoyRequestMinBytes, gateway::kDecoyRequestMaxBytes)));
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
    std::uint64_t carrySeen = carryReturns();

    while (live_.load()) {
        std::this_thread::sleep_for(kCoverTick);
        if (!live_.load()) {
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        reattachOrphans();
        if (const std::uint64_t carry = carryReturns(); carry != carrySeen) {
            carrySeen = carry;
            openAt = now;
            backoff = kFirstRetry;
        }

        if (!hasControl()) {
            if (now < openAt) {
                continue;
            }
            try {
                openControl();
                if (openFailing_.exchange(false)) {
                    noteCarryReturned();
                }
                backoff = kFirstRetry;
                churnAt = nextChurn();
            } catch (const std::exception& error) {
                openFailing_.store(true);
                bazarish::log::warn(
                    "i2p: the gateway would not take a socket: {}", error.what());
                openAt = std::chrono::steady_clock::now() + backoff;
                backoff = std::min(backoff * 2, kSlowestRetry);
                if (millisNow() - link_->aloneSince.load()
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

bool GatewayRouter::attach(const std::uint32_t flow)
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
    const gateway::ChannelOpened opened = openChannelSocket(
        [this](const http::SocketPtr& socket, const std::vector<unsigned char>& message) {
            arrived(socket, message);
        },
        [link = link_, flow](const http::SocketPtr&) {
            const std::lock_guard<std::mutex> lock(link->mutex);
            link->flows.erase(flow);
            link->orphaned.insert(flow);
        });
    if (opened.socket == nullptr) {
        bazarish::log::debug("i2p: no socket of its own for flow {}: {}", flow, opened.error);
        return false;
    }
    if (opened.welcome.has_value()) {
        bazarish::log::warn("i2p: the gateway's session was gone when flow {} asked for a socket",
            flow);
        opened.socket->close();
        return false;
    }
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->flows[flow] = opened.socket;
    }
    opened.socket->send(gateway::encodeJson(FrameType::eAttach, flow, nlohmann::json::object()));
    return true;
}

void GatewayRouter::reattachOrphans()
{
    std::vector<std::uint32_t> again;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        for (auto at = link_->orphaned.begin(); at != link_->orphaned.end();) {
            const auto endpoint = link_->endpoints.find(*at);
            if (endpoint == link_->endpoints.end() || endpoint->second.expired()) {
                at = link_->orphaned.erase(at);
                continue;
            }
            again.push_back(*at);
            ++at;
        }
    }
    for (const std::uint32_t flow : again) {
        if (attach(flow)) {
            const std::lock_guard<std::mutex> lock(link_->mutex);
            link_->orphaned.erase(flow);
        }
    }
}

std::optional<Frame> Link::call(
    const Bytes& frame, const std::uint32_t ref, const std::chrono::seconds timeout)
{
    const std::shared_ptr<Pending> pending = expect(frame, ref);
    send(frame);
    return await(pending, ref, timeout);
}

std::shared_ptr<Pending> Link::expect(const Bytes& frame, const std::uint32_t ref)
{
    const std::shared_ptr<Pending> pending = std::make_shared<Pending>();
    pending->request = frame;
    const std::lock_guard<std::mutex> lock(mutex);
    awaited[ref] = pending;
    return pending;
}

std::optional<Frame> Link::await(const std::shared_ptr<Pending>& pending,
    const std::uint32_t ref, const std::chrono::seconds timeout)
{
    bool live = false;
    {
        const std::lock_guard<std::mutex> lock(mutex);
        live = control != nullptr && control->open();
    }
    const Bytes& frame = pending->request;

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
        return std::nullopt;
    }
    return answer;
}

void Link::remember(const std::uint32_t id, const std::shared_ptr<StreamState>& stream)
{
    const std::lock_guard<std::mutex> lock(mutex);
    streams[id] = stream;
}

void Link::release(const std::uint32_t id)
{
    const std::lock_guard<std::mutex> lock(mutex);
    streams.erase(id);
}

void Link::endStreamsOf(const std::uint32_t endpoint)
{
    std::vector<std::shared_ptr<Pending>> dials;
    {
        const std::lock_guard<std::mutex> lock(mutex);
        for (const auto& [id, held] : streams) {
            const std::shared_ptr<StreamState> stream = held.lock();
            if (stream == nullptr || stream->endpoint() != endpoint) {
                continue;
            }
            stream->reset();
            const auto dialling = awaited.find(id);
            if (dialling != awaited.end()) {
                dials.push_back(dialling->second);
            }
        }
    }
    for (const std::shared_ptr<Pending>& dial : dials) {
        {
            const std::lock_guard<std::mutex> lock(dial->mutex);
            dial->done = true;
        }
        dial->answered.notify_all();
    }
}

void Link::abandonCalls()
{
    std::vector<std::shared_ptr<Pending>> calls;
    {
        const std::lock_guard<std::mutex> lock(mutex);
        for (const auto& [ref, pending] : awaited) {
            calls.push_back(pending);
        }
    }
    for (const std::shared_ptr<Pending>& call : calls) {
        {
            const std::lock_guard<std::mutex> lock(call->mutex);
            call->done = true;
        }
        call->answered.notify_all();
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
    if (config.keys.has_value() && config.leaseSetReaders.empty()) {
        notWithAGateway("a destination built from a key of your own");
    }
    const std::uint32_t id = link_->nextId();
    const bool raw = config.traffic == Traffic::eRaw;
    nlohmann::json ask = {{"kind", raw ? "raw" : "stream"},
        {"published", config.published}, {"realtime", config.realtime}};
    if (!config.target.empty()) {
        ask["target"] = config.target;
    }
    if (config.keys.has_value()) {
        ask["keys"] = config.keys->issueTransient(kFirstDelegationDays).privateBase64();
        nlohmann::json readers = nlohmann::json::array();
        for (const Bytes& reader : config.leaseSetReaders) {
            readers.push_back(leaseSetKeyBase64(reader));
        }
        ask["readers"] = readers;
    }
    if (!config.leaseSetReaderKey.empty()) {
        ask["readerKey"] = leaseSetKeyBase64(config.leaseSetReaderKey);
    }
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->creating[id] = std::nullopt;
    }
    const std::optional<Frame> answer
        = link_->call(gateway::encodeJson(FrameType::eEndpointCreate, id, ask), id,
            kCallTimeout);
    const std::string host = answer && answer->type == FrameType::eOk
        ? gateway::bodyJson(*answer).value("host", std::string()) : std::string();
    if (host.empty()) {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->creating.erase(id);
    }
    if (!answer) {
        throw std::runtime_error("bazarish::i2p: the gateway did not answer in time");
    }
    if (answer->type != FrameType::eOk) {
        const nlohmann::json said = answer->type == FrameType::eError
            ? gateway::bodyJson(*answer) : nlohmann::json::object();
        throw GatewayRefusal("bazarish::i2p: the gateway refused a destination: "
            + said.value("code", std::string()) + ": " + said.value("message", std::string()));
    }
    if (host.empty()) {
        throw std::runtime_error("bazarish::i2p: the gateway named no address");
    }
    const auto endpoint = std::make_shared<GatewayEndpoint>(link_, id, host, raw,
        config.published, config.label, config.accountLabel, config.target, config.keys);
    {
        // Under the lock, so a status that comes after it lands on top of it.
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->endpoints[id] = endpoint;
        const auto early = link_->creating.find(id);
        if (early->second) {
            const nlohmann::json body = gateway::bodyJson(*early->second);
            endpoint->statusChanged(body.value("ready", false), body.value("tunnelsIn", 0),
                body.value("tunnelsOut", 0), body.value("leaseSets", 0),
                body.value("localRoute", false));
        }
        link_->creating.erase(early);
    }
    if (raw || config.bulk) {
        if (!attach(id)) {
            const std::lock_guard<std::mutex> lock(link_->mutex);
            link_->orphaned.insert(id);
        }
    }
    return endpoint;
}

// The last owner may let go meanwhile, and an endpoint's destructor takes the link's mutex.
std::vector<std::shared_ptr<GatewayEndpoint>> GatewayRouter::endpointsHeld() const
{
    std::vector<std::shared_ptr<GatewayEndpoint>> standing;
    const std::lock_guard<std::mutex> lock(link_->mutex);
    for (const auto& [id, held] : link_->endpoints) {
        (void)id;
        if (std::shared_ptr<GatewayEndpoint> endpoint = held.lock()) {
            standing.push_back(std::move(endpoint));
        }
    }
    return standing;
}

void GatewayRouter::retagEndpoint(
    const EndpointBackend& endpoint, std::string label, std::string accountLabel)
{
    for (const std::shared_ptr<GatewayEndpoint>& mine : endpointsHeld()) {
        if (mine.get() == &endpoint) {
            mine->retag(std::move(label), std::move(accountLabel));
            return;
        }
    }
}

std::vector<LocalDestination> GatewayRouter::localDestinations() const
{
    std::vector<LocalDestination> destinations;
    for (const std::shared_ptr<GatewayEndpoint>& endpoint : endpointsHeld()) {
        LocalDestination entry;
        entry.label = endpoint->label();
        entry.accountLabel = endpoint->accountLabel();
        entry.host = endpoint->routingHost();
        entry.published = endpoint->published();
        entry.ready = endpoint->ready();
        entry.inboundTunnels = endpoint->inboundTunnels();
        entry.outboundTunnels = endpoint->outboundTunnels();
        entry.remoteLeaseSets = endpoint->leaseSets();
        entry.localRoute = endpoint->localRoute();
        destinations.push_back(std::move(entry));
    }
    return destinations;
}

LeaseSetRefresh GatewayRouter::refreshLeaseSet(
    const std::string& localHost, const std::string& remoteHost)
{
    std::shared_ptr<GatewayEndpoint> from;
    for (const std::shared_ptr<GatewayEndpoint>& endpoint : endpointsHeld()) {
        if (endpoint->routingHost() == localHost) {
            from = endpoint;
        }
    }
    if (from == nullptr) {
        throw std::runtime_error("bazarish::i2p: no destination " + localHost + " to look up from");
    }
    const std::uint32_t id = link_->nextId();
    const nlohmann::json ask = {{"endpoint", from->id()}, {"host", remoteHost}};
    const std::optional<Frame> answer
        = link_->call(gateway::encodeJson(FrameType::eLeaseSetRefresh, id, ask), id, kCallTimeout);
    if (!answer) {
        throw std::runtime_error(
            "bazarish::i2p: the gateway did not answer a lease set lookup in time");
    }
    if (answer->type != FrameType::eOk) {
        const nlohmann::json said = answer->type == FrameType::eError
            ? gateway::bodyJson(*answer) : nlohmann::json::object();
        throw GatewayRefusal("bazarish::i2p: the gateway refused a lease set lookup: "
            + said.value("message", std::string(gateway::frameTypeName(answer->type))));
    }
    return gateway::leaseSetRefreshFromJson(gateway::bodyJson(*answer));
}

void GatewayRouter::arrived(
    const http::SocketPtr&, const std::vector<unsigned char>& message)
{
    link_->lastArrival.store(millisNow());
    try {
        dispatch(gateway::decode(message));
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
    if (waiting != nullptr && answers(frame.type)) {
        const std::lock_guard<std::mutex> lock(waiting->mutex);
        waiting->answer = frame;
        waiting->done = true;
        waiting->answered.notify_all();
        return;
    }

    std::shared_ptr<GatewayEndpoint> endpoint;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        const auto atEndpoint = link_->endpoints.find(frame.ref);
        if (atEndpoint != link_->endpoints.end()) {
            endpoint = atEndpoint->second.lock();
        }
    }

    switch (frame.type) {
        case FrameType::eTickets: {
            const nlohmann::json body = gateway::bodyJson(frame);
            const std::lock_guard<std::mutex> lock(link_->mutex);
            for (const nlohmann::json& ticket : body.at("tickets")) {
                link_->tickets.push_back(fromBase64(ticket.get<std::string>()));
            }
            return;
        }
        case FrameType::eEndpointStatus: {
            if (endpoint == nullptr) {
                const std::lock_guard<std::mutex> lock(link_->mutex);
                const auto early = link_->creating.find(frame.ref);
                if (early != link_->creating.end()) {
                    early->second = frame;
                }
                return;
            }
            const nlohmann::json body = gateway::bodyJson(frame);
            endpoint->statusChanged(body.value("ready", false), body.value("tunnelsIn", 0),
                body.value("tunnelsOut", 0), body.value("leaseSets", 0),
                body.value("localRoute", false));
            return;
        }
        case FrameType::eEndpointLost: {
            if (endpoint != nullptr) {
                endpoint->lost();
            }
            return;
        }
        case FrameType::eEndpointRenew: {
            if (endpoint != nullptr) {
                endpoint->renewDelegation();
            }
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
        case FrameType::eStreamCredit:
        case FrameType::eStreamClose:
        case FrameType::eStreamReset:
            deliver(frame);
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

void GatewayRouter::deliver(const Frame& frame)
{
    const std::lock_guard<std::mutex> handing(link_->delivering);
    std::shared_ptr<StreamState> stream;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        const auto found = link_->streams.find(frame.ref);
        if (found == link_->streams.end()) {
            return;
        }
        stream = found->second.lock();
    }
    if (stream == nullptr) {
        return;
    }
    switch (frame.type) {
        case FrameType::eStreamData:
            stream->arrived(frame.body);
            return;
        case FrameType::eStreamCredit:
            stream->creditedBy(gateway::decodeCredit(frame));
            return;
        case FrameType::eStreamClose:
            stream->farSideFinished();
            return;
        case FrameType::eStreamReset:
            stream->reset();
            return;
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
