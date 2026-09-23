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

// A flow gets a socket of its own when it is created and never afterwards. A
// live stream cannot be moved: the counts the attach exchanges make the move
// lossless but not ordered, and frames already queued on the socket being left
// arrive behind frames on the one being joined. Ordering that would need a
// sequence number this wire does not carry. Media is attached at creation,
// before there is anything to reorder, and a stream stays where it started.
// How long a caller waits for an answer to a request before giving up on the
// gateway rather than on the operation.
constexpr std::chrono::seconds kCallTimeout{60};
// How often a blocked reader looks again at whether anything arrived, and how
// often the cover thread looks at its two clocks.
constexpr std::chrono::milliseconds kPoll{20};
constexpr std::chrono::milliseconds kCoverTick{200};
// A control socket is replaced at a quiet moment, not in the middle of one: it
// must have carried nothing for this long, and have nothing outstanding.
constexpr std::chrono::milliseconds kQuietBeforeChurn{1000};

std::int64_t millisNow()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// A number between the two, from the system's random source.
std::chrono::milliseconds drawBetween(
    const std::chrono::milliseconds low, const std::chrono::milliseconds high)
{
    if (high <= low) {
        return low;
    }
    const Bytes draw = randomBytes(sizeof(std::uint64_t));
    std::uint64_t value = 0;
    for (const unsigned char byte : draw) {
        value = (value << 8) | byte;
    }
    const std::uint64_t span = static_cast<std::uint64_t>((high - low).count()) + 1;
    return low + std::chrono::milliseconds(static_cast<std::int64_t>(value % span));
}

std::size_t drawBetween(const std::size_t low, const std::size_t high)
{
    if (high <= low) {
        return low;
    }
    const Bytes draw = randomBytes(sizeof(std::uint64_t));
    std::uint64_t value = 0;
    for (const unsigned char byte : draw) {
        value = (value << 8) | byte;
    }
    return low + static_cast<std::size_t>(value % (high - low + 1));
}

[[noreturn]] void notWithAGateway(const char* const what)
{
    throw std::runtime_error(
        std::string("bazarish::i2p: ") + what + " is not something a gateway can answer");
}

// One request waiting for the answer that carries its reference. It keeps the
// frame it sent: a control socket is replaced on a timer, and a request that
// was in flight when its socket went is a request nobody will ever answer
// unless it is asked again.
struct Pending {
    std::mutex mutex;
    std::condition_variable answered;
    bool done = false;
    Frame answer;
    Bytes request;
};

class GatewayStream;
class GatewayEndpoint;

// What a stream or a destination needs from the connection, held by shared_ptr
// so that one of them outliving the router is a flow that stops working rather
// than a write into a dead object. The embedded transport keeps its owner alive
// the same way, and at process exit a destination really can outlive the router
// that made it.
class Link {
public:
    explicit Link(const bool odd) : ids_(odd) {}

    std::uint32_t nextId() { return ids_.next(); }
    void send(const Bytes& frame);
    http::SocketPtr socketFor(std::uint32_t flow) const;
    // A stream's own socket, else its destination's, else none.
    http::SocketPtr socketFor(std::uint32_t stream, std::uint32_t endpoint) const;
    // Sends and waits for the answer that carries the same reference.
    Frame call(const Bytes& frame, std::uint32_t ref, std::chrono::seconds timeout);
    void forget(std::uint32_t id);
    // A stream is owned by whoever asked for it, so this holds a pointer and
    // the stream says when it goes.
    void remember(std::uint32_t id, GatewayStream* stream);

    mutable std::mutex mutex;
    gateway::Ids ids_;
    http::SocketPtr control;
    std::string cookie;
    std::map<std::uint32_t, std::shared_ptr<Pending>> awaited;
    std::map<std::uint32_t, std::weak_ptr<GatewayEndpoint>> endpoints;
    std::map<std::uint32_t, GatewayStream*> streams;
    std::map<std::uint32_t, http::SocketPtr> flows;
    // Frames written while there is no control socket. The gap is seconds and
    // the session outlives it, so they wait rather than fail.
    std::deque<Bytes> waiting;
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
    // Bytes handed over that have not left this device yet: what is still
    // waiting for a window, and what the window holds uncredited.
    std::size_t pendingBytes() const override;
    void close() override;

    std::uint32_t id() const { return id_; }
    // Bytes the gateway sent for this stream.
    void arrived(const Bytes& data);
    void creditedBy(std::uint64_t total);
    // How much this side has taken in, which is what a resume tells the
    // gateway, and what it has sent that the gateway has not confirmed, which
    // is what goes out again.
    std::uint64_t received() const { return book_.received(); }
    std::vector<Bytes> replayFrames(std::uint64_t peerReceived);
    void farSideFinished();
    void reset();

private:
    // Moves what is queued into the window, as far as it reaches.
    void drain();

    std::shared_ptr<Link> link_;
    std::uint32_t id_;
    // A stream with no socket of its own rides its destination's, when that
    // destination has one, and the main socket otherwise.
    std::uint32_t endpoint_;
    gateway::StreamBook book_;
    std::chrono::seconds readTimeout_{0};
    mutable std::mutex mutex_;
    std::condition_variable arrived_;
    std::deque<unsigned char> inbox_;
    // Written by the caller and not yet inside the window. A write queues and
    // returns, as it does on every other transport; what bounds it is the
    // caller watching pendingBytes(), not this.
    std::deque<unsigned char> outbox_;
    bool finished_ = false;
    bool closed_ = false;
    bool endWhenDrained_ = false;
};

class GatewayEndpoint : public EndpointBackend {
public:
    GatewayEndpoint(std::shared_ptr<Link> link, std::uint32_t id, std::string host, bool raw);
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
    std::shared_ptr<Link> link_;
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
        , link_(std::make_shared<Link>(/*odd=*/false))
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
    // In service, which a session is across a gap between control sockets: the
    // client drops its own on purpose, and the session outlives it.
    bool running() const override { return live_.load(); }
    // There is a control socket right now. The gateway's own tunnels are its
    // business; what this side can honestly say is whether it can be reached.
    bool ready() const override;

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

    // Gives a flow a socket of its own, at the moment it is created.
    void attach(std::uint32_t flow, std::uint64_t received);

private:
    void arrived(const http::SocketPtr& socket, const std::vector<unsigned char>& message);
    void dispatch(const Frame& frame);
    http::SocketDial dialFor() const;
    // Opens a control socket, says hello, and puts back what a socket that died
    // left unfinished. Throws when the gateway will not have it.
    void openControl();
    void closeControl();
    // The timers that make this look like a host being fetched from rather than
    // one connection that lives for hours.
    void coverLoop();
    void decoy();
    bool quiet() const;
    // Gives up on a session the gateway can no longer be holding, so what was
    // written for it stops accumulating for nothing.
    void abandon();

    RouterConfig config_;
    std::shared_ptr<Link> link_;
    std::thread cover_;
    std::atomic<bool> live_{false};
    // When the control socket went away, which is when the gateway's own clock
    // on this session started.
    std::atomic<std::int64_t> aloneSince_{0};
    std::atomic<int> known_{0};
    std::atomic<int> floodfills_{0};
    std::atomic<int> inbound_{0};
    std::atomic<int> outbound_{0};
};

// --- stream ---

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
    // Counted before it is readable, not after: a reader woken by the insert
    // credits what it read, and crediting bytes the book has not been told
    // about yet is reading more than ever arrived.
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

    // Read means consumed, and a credit is the total consumed so far. It goes
    // out where this stream's data goes: a lane carries a stream's data, its
    // credits and its end, or it is not that stream's lane.
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
    // Under the one lock from first byte to last: a write and an arriving
    // credit both drain, and what keeps their frames in order is this lock. A
    // data frame that overtakes another is a corrupted stream.
    bool ending = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const http::SocketPtr own = link_->socketFor(id_, endpoint_);
        while (!outbox_.empty()) {
            // Never more than the window the gateway granted, and never more
            // than one message: a message cannot be interleaved with another,
            // so its length is how long anything else waits behind it.
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
    return outbox_.size() + book_.pending();
}

void GatewayStream::creditedBy(const std::uint64_t total)
{
    book_.peerCredited(total);
    // Room here is room for what is queued behind it.
    drain();
}

void GatewayStream::close()
{
    bool tell = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        tell = !closed_;
        closed_ = true;
        // The end goes out behind the bytes it ends. One that overtook them
        // would be a truncated file at the far end.
        endWhenDrained_ = tell;
    }
    if (tell) {
        drain();
    }
    arrived_.notify_all();
}

// --- endpoint ---

GatewayEndpoint::GatewayEndpoint(
    std::shared_ptr<Link> link, const std::uint32_t id, std::string host, const bool raw)
    : link_(std::move(link))
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
    const std::uint32_t id = link_->nextId();
    auto stream = std::make_unique<GatewayStream>(link_, id, id_);
    const Bytes ask = gateway::encodeJson(FrameType::eStreamOpen, id,
        {{"endpoint", id_}, {"host", host}, {"deadline", timeout.count()}});
    // The whole deadline travels: the gateway re-issues the dial until it runs
    // out, because a LeaseSet that is not in the netDb yet is a reason to try
    // again rather than to fail.
    const Frame answer = link_->call(ask, id, timeout + kCallTimeout);
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
    const http::SocketPtr out = link_->socketFor(id_);
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
    link_->send(gateway::encode(FrameType::eEndpointStop, id_));
    link_->forget(id_);
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
    const std::lock_guard<std::mutex> lock(link_->mutex);
    return live_.load() && link_->control != nullptr && link_->control->open();
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

    // Said on the socket itself rather than through send(), which would queue
    // it behind whatever is waiting for a socket that is not up yet.
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

    // What is still standing, and what is not. A stream the gateway does not
    // name is gone whatever the reason, and saying so beats letting a reader
    // wait for bytes that are never coming.
    nlohmann::json ours = nlohmann::json::array();
    std::vector<Bytes> replay;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->cookie = body.value("session", std::string());
        std::map<std::uint32_t, std::uint64_t> alive;
        if (const auto found = body.find("streams"); found != body.end() && found->is_array()) {
            for (const nlohmann::json& one : *found) {
                alive[one.value("id", 0U)] = one.value("received", std::uint64_t{0});
            }
        }
        for (const auto& [streamId, stream] : link_->streams) {
            const auto found = alive.find(streamId);
            if (found == alive.end()) {
                if (resumed) {
                    stream->reset();
                }
                continue;
            }
            ours.push_back({{"id", streamId}, {"received", stream->received()}});
            // Built here, under the lock that keeps the stream alive: the map
            // holds pointers to objects their callers own.
            for (Bytes& frame : stream->replayFrames(found->second)) {
                replay.push_back(std::move(frame));
            }
        }
        if (const auto found = body.find("endpoints"); found != body.end() && found->is_array()) {
            for (const nlohmann::json& one : *found) {
                const auto at = link_->endpoints.find(one.value("id", 0U));
                if (at == link_->endpoints.end()) {
                    continue;
                }
                if (const std::shared_ptr<GatewayEndpoint> endpoint = at->second.lock()) {
                    endpoint->statusChanged(one.value("ready", false), one.value("tunnelsIn", 0),
                        one.value("tunnelsOut", 0), one.value("leaseSets", 0));
                }
            }
        }
    }
    if (!ours.empty()) {
        const Bytes resume
            = gateway::encodeJson(FrameType::eResume, link_->nextId(), {{"streams", ours}});
        opened.socket->send(std::vector<unsigned char>(resume.begin(), resume.end()));
    }
    // This side's own unconfirmed bytes, in order, before anything new.
    for (const Bytes& frame : replay) {
        opened.socket->send(std::vector<unsigned char>(frame.begin(), frame.end()));
    }

    // Anything asked and not yet answered goes again, with the same reference:
    // identifiers are never reused, so the gateway answers a repeat from what
    // it already did rather than doing it twice.
    std::vector<Bytes> again;
    std::deque<Bytes> held;
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        for (const auto& [ref, request] : link_->awaited) {
            (void)ref;
            const std::lock_guard<std::mutex> waiting(request->mutex);
            if (!request->done && !request->request.empty()) {
                again.push_back(request->request);
            }
        }
        link_->control = opened.socket;
        held.swap(link_->waiting);
        link_->lastUse.store(millisNow());
    }
    for (const Bytes& frame : again) {
        opened.socket->send(std::vector<unsigned char>(frame.begin(), frame.end()));
    }
    for (const Bytes& frame : held) {
        opened.socket->send(std::vector<unsigned char>(frame.begin(), frame.end()));
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
    const Bytes noise = randomBytes(
        drawBetween(gateway::kDecoyRequestMinBytes, gateway::kDecoyRequestMaxBytes));
    // The answer is thrown away. Its length was never this side's to choose.
    (void)http::probeHost(dialFor(), std::string(noise.begin(), noise.end()));
}

void GatewayRouter::coverLoop()
{
    // Zero takes the protocol's own figure, which is what a deployment with no
    // opinion wants.
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
    while (live_.load()) {
        std::this_thread::sleep_for(kCoverTick);
        if (!live_.load()) {
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= decoyAt) {
            decoy();
            decoyAt = nextDecoy();
        }
        if (!live_.load() || now < churnAt) {
            continue;
        }
        // A socket carrying something is not dropped: the draw is taken at the
        // next quiet moment instead.
        if (!quiet()) {
            continue;
        }
        closeControl();
        std::this_thread::sleep_for(drawBetween(std::min(decoyMin, maxGap), maxGap));
        if (!live_.load()) {
            break;
        }
        try {
            openControl();
        } catch (const std::exception& error) {
            bazarish::log::warn("i2p: the gateway would not take a new socket: {}", error.what());
            // Past the term a session lasts there is nothing left at the far
            // end to come back to, and what is queued for it is queued for
            // nothing.
            if (millisNow() - aloneSince_.load()
                > std::chrono::milliseconds(gateway::kSessionTtl).count()) {
                abandon();
            }
        }
        churnAt = nextChurn();
    }
}

void Link::send(const Bytes& frame)
{
    http::SocketPtr socket;
    {
        const std::lock_guard<std::mutex> lock(mutex);
        if (control == nullptr) {
            // Between control sockets. A stream's data is not queued here: the
            // bytes are still held against their window, and the resume on the
            // next socket puts them back in order. Queueing them as well would
            // send them twice, once behind the replay.
            if (!frame.empty()
                && static_cast<FrameType>(frame.front()) != FrameType::eStreamData) {
                // The gap is seconds and the session outlives it, so the rest
                // waits rather than disappearing.
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

void GatewayRouter::attach(const std::uint32_t flow, const std::uint64_t received)
{
    if (flow == 0) {
        return;
    }
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        if (link_->flows.count(flow) > 0 || link_->flows.size() + 1 >= gateway::kMaxSocketsPerSession) {
            return;
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
        });
    if (opened.socket == nullptr) {
        // A flow without a socket of its own rides the main one. Slower under
        // load, and not a failure.
        bazarish::log::debug("i2p: no socket of its own for flow {}: {}", flow, opened.error);
        return;
    }
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->flows[flow] = opened.socket;
    }
    opened.socket->send(gateway::encodeJson(FrameType::eAttach, flow, {{"received", received}}));
}

Frame Link::call(
    const Bytes& frame, const std::uint32_t ref, const std::chrono::seconds timeout)
{
    const std::shared_ptr<Pending> pending = std::make_shared<Pending>();
    pending->request = frame;
    {
        const std::lock_guard<std::mutex> lock(mutex);
        awaited[ref] = pending;
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
    const std::uint32_t id = link_->nextId();
    // In this client the two coincide exactly: raw datagrams carry a call's
    // media and nothing else, and a call's media is the only destination that
    // asks for the realtime lane. A raw destination that is not realtime would
    // need a kind of its own in the configuration.
    const bool raw = config.realtime;
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
    const auto endpoint = std::make_shared<GatewayEndpoint>(link_, id, host, raw);
    {
        const std::lock_guard<std::mutex> lock(link_->mutex);
        link_->endpoints[id] = endpoint;
    }
    if (raw || config.bulk) {
        // A destination that carries media, or one raised for a single
        // transfer, takes a socket of its own at creation - before there is
        // anything in flight to be reordered by the move that giving it one
        // later would be. Everything on it then has a queue of its own.
        attach(id, 0);
    }
    return endpoint;
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
