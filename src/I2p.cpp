// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "bazarish/I2pAddress.hpp"
#include "bazarish/Log.hpp"

#include <utility>

#include <boost/asio.hpp>

#include "api.h"
#include "Base.h"
#include "Blinding.h"
#include "Crypto.h"
#include "Datagram.h"
#include "Destination.h"
#include "Identity.h"
#include "Log.h"
#include "NetDb.hpp"
#include "RouterInfo.h"
#include "NTCP2.h"
#include "SSU2.h"
#include "Streaming.h"
#include "Transports.h"
#include "Tunnel.h"
#include "TunnelPool.h"
#include "util.h"
#include "version.h"

#include <algorithm>
#include <fstream>
#include <map>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// Reach the embedded i2pd engine. Inside namespace bazarish::i2p the bare name
// "i2p" resolves to our own namespace, so the engine must be addressed through
// this alias.
namespace i2pd = ::i2p;

namespace bazarish::i2p {
namespace {

constexpr i2pd::data::SigningKeyType kSigType = i2pd::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519;
constexpr std::size_t kB32SuffixLen = 8;  // ".b32.i2p"

// libi2pd's crypto state must be initialised once before any key operation. With
// precomputation=false this is a cheap no-op-safe call; the guard keeps it once.
void ensureCryptoInit()
{
    static const bool kInit = []() { i2pd::crypto::InitCrypto(false); return true; }();
    (void)kInit;
}

bazarish::log::Level mapLevel(LogLevel level)
{
    switch (level)
    {
        case eLogNone:
        case eLogCritical:
        case eLogError:   return bazarish::log::Level::eError;
        case eLogWarning: return bazarish::log::Level::eWarn;
        case eLogInfo:    return bazarish::log::Level::eInfo;
        default:          return bazarish::log::Level::eDebug;
    }
}

i2pd::data::PrivateKeys parseKeys(const Bytes& blob)
{
    ensureCryptoInit();
    i2pd::data::PrivateKeys keys;
    if (blob.empty() || keys.FromBuffer(blob.data(), blob.size()) == 0)
    {
        throw std::runtime_error("bazarish::i2p: malformed private keys blob");
    }
    return keys;
}

Bytes serializeKeys(const i2pd::data::PrivateKeys& keys)
{
    Bytes out(keys.GetFullLen());
    const std::size_t n = keys.ToBuffer(out.data(), out.size());
    out.resize(n);
    return out;
}

void privacyToTunnel(Privacy privacy, int& length, int& variance)
{
    switch (privacy)
    {
        case Privacy::eMinimal: length = 1; variance = 0; break;
        case Privacy::eMiddle:  length = 1; variance = 1; break;
        case Privacy::eMax:     length = 3; variance = 0; break;
    }
}

bool isClosedStatus(i2pd::stream::StreamStatus status)
{
    return status == i2pd::stream::eStreamStatusReset
        || status == i2pd::stream::eStreamStatusClosed
        || status == i2pd::stream::eStreamStatusTerminated;
}

// A pool of single-threaded asio io_contexts ("lanes"). Each i2pd
// ClientDestination is pinned to ONE lane for its lifetime, so every handler of a
// given destination (garlic/leaseset/streaming/datagram) runs on that lane's one
// thread and never two at once. This is required: an i2pd destination is not safe
// under concurrent handler execution - its per-destination state (e.g. the
// ECIES-X25519 tag map) has no internal locking and assumes a single service
// thread, so running one destination across several threads corrupts it. New
// destinations are handed out round-robin across the lanes, so a router still
// hosts many destinations and uses several cores in parallel - it just never runs
// two threads inside the same destination. Each destination used to be a
// RunnableClientDestination (its own thread), which capped a server at one OS
// thread per destination; the lane pool keeps that scaling without the per-dest
// thread and without the cross-thread races a single shared multi-thread context
// caused. Held via shared_ptr by both the Router and every Endpoint it spawns, so
// the pool outlives the destinations regardless of teardown order.
class IoService {
public:
    explicit IoService(std::size_t lanes)
    {
        if (lanes < 1) { lanes = 1; }
        lanes_.reserve(lanes);
        for (std::size_t i = 0; i < lanes; ++i)
        {
            lanes_.push_back(std::make_unique<Lane>());
        }
        // Start the threads only after all lanes exist, so the vector never
        // reallocates under a running worker (the worker captures a stable Lane*).
        for (auto& lane : lanes_)
        {
            Lane* const l = lane.get();
            l->worker = std::thread([l]
            {
                // The work guard keeps run() blocked while idle; it returns only
                // on shutdown (guard released + stop) or when a handler throws, in
                // which case we log and resume so one bad packet cannot permanently
                // kill the lane.
                while (l->running)
                {
                    try
                    {
                        l->ctx.run();
                    }
                    catch (const std::exception& ex)
                    {
                        bazarish::log::emit(bazarish::log::Level::eError,
                            std::string("bazarish::i2p: io_context handler exception: ") + ex.what());
                    }
                }
            });
        }
    }

    ~IoService()
    {
        for (auto& lane : lanes_)
        {
            lane->running = false;
            lane->work.reset();
            lane->ctx.stop();
        }
        for (auto& lane : lanes_)
        {
            if (lane->worker.joinable()) { lane->worker.join(); }
        }
    }

    // The io_context a new destination should run on (round-robin across lanes).
    // The chosen lane's single thread serializes all of that destination's
    // handlers, while different destinations spread across lanes run in parallel.
    boost::asio::io_context& next()
    {
        const std::size_t i = nextLane_.fetch_add(1, std::memory_order_relaxed) % lanes_.size();
        return lanes_[i]->ctx;
    }

private:
    struct Lane {
        boost::asio::io_context ctx;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work
            = boost::asio::make_work_guard(ctx);
        std::atomic<bool> running{true};
        std::thread worker;
    };
    std::vector<std::unique_ptr<Lane>> lanes_;
    std::atomic<std::size_t> nextLane_{0};
};

// Number of lanes (single-threaded io_contexts) for the destination pool: half
// the hardware concurrency, clamped to [2, 8]. The destination layer (streaming,
// datagrams, leaseset/garlic handling) runs here alongside the i2pd engine's own
// transport and tunnel threads, so a fraction of the cores is plenty and leaves
// headroom for the engine.
std::size_t ioContextCount()
{
    const unsigned hw = std::thread::hardware_concurrency();
    const std::size_t half = hw ? hw / 2 : 2;
    return std::clamp<std::size_t>(half, 2, 8);
}

// One embedded router per process (the i2pd engine is process-global).
std::atomic<bool> g_routerLive{false};

// libi2pd log output gate. OFF by default: the engine's logging is fully
// suppressed (nothing reaches bazarish::log) until a caller turns it on.
std::atomic<bool> g_i2pLogging{false};

}  // namespace

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

struct Keys::Impl {
    i2pd::data::PrivateKeys keys;
};

Keys::Keys() : impl_(std::make_unique<Impl>()) {}
Keys::Keys(const Keys& other) : impl_(std::make_unique<Impl>(*other.impl_)) {}
Keys::Keys(Keys&&) noexcept = default;
Keys& Keys::operator=(const Keys& other) { impl_ = std::make_unique<Impl>(*other.impl_); return *this; }
Keys& Keys::operator=(Keys&&) noexcept = default;
Keys::~Keys() = default;

Keys Keys::generate()
{
    ensureCryptoInit();
    Keys k;
    k.impl_->keys = i2pd::data::PrivateKeys::CreateRandomKeys(kSigType);
    return k;
}

Keys Keys::fromBlob(const Bytes& blob)
{
    Keys k;
    k.impl_->keys = parseKeys(blob);
    return k;
}

Bytes Keys::blob() const { return serializeKeys(impl_->keys); }
std::string Keys::privateBase64() const { return impl_->keys.ToBase64(); }
std::string Keys::publicBase64() const { return impl_->keys.GetPublic()->ToBase64(); }
std::string Keys::base32() const { return impl_->keys.GetPublic()->GetIdentHash().ToBase32(); }
bool Keys::isOffline() const { return impl_->keys.IsOfflineSignature(); }

Keys Keys::issueTransient(std::int64_t expiresUnix) const
{
    Keys t;
    t.impl_->keys = impl_->keys.CreateOfflineKeys(kSigType, static_cast<std::uint32_t>(expiresUnix));
    return t;
}

// ---------------------------------------------------------------------------
// routingHost
// ---------------------------------------------------------------------------

std::string routingHost(const std::string& publicBase64, LeaseSetKind kind)
{
    return kind == LeaseSetKind::eEncrypted
        ? encryptedLeaseSetHost(publicBase64)
        : standardLeaseSetHost(publicBase64);
}

std::string routerVersion()
{
    // The upstream i2pd version baked into the embedded engine (e.g. "2.60.0").
    return I2PD_VERSION;
}

std::vector<Bytes> sampleRouterInfos(const std::size_t count)
{
    // GetRandomRouter may repeat, so collect by identity until the netDb has
    // nothing new left to give rather than looping forever on a small netDb.
    std::map<std::string, Bytes> unique;
    const std::size_t attempts = count * 8;
    for (std::size_t i = 0; i < attempts && unique.size() < count; ++i)
    {
        const std::shared_ptr<const i2pd::data::RouterInfo> router
            = i2pd::data::netdb.GetRandomRouter();
        if (!router || router->GetBuffer() == nullptr || router->GetBufferLen() == 0)
        {
            continue;
        }
        unique.emplace(router->GetIdentHashBase64(),
            Bytes(router->GetBuffer(), router->GetBuffer() + router->GetBufferLen()));
    }
    std::vector<Bytes> sample;
    sample.reserve(unique.size());
    for (auto& [ident, buffer] : unique) { sample.push_back(std::move(buffer)); }
    return sample;
}

std::size_t seedRouterInfos(
    const std::filesystem::path& dataDir, const std::vector<Bytes>& routers)
{
    ensureCryptoInit();
    const std::filesystem::path netDb = dataDir / "netDb";
    std::size_t written = 0;
    for (const Bytes& buffer : routers)
    {
        if (buffer.empty()) { continue; }
        // Parsing validates the RouterInfo (including its signature) and gives us
        // the identity the on-disk layout is keyed by; a bad entry is skipped.
        const i2pd::data::RouterInfo router(buffer.data(), buffer.size());
        const std::string ident = router.GetIdentHashBase64();
        if (ident.empty()) { continue; }
        std::string safeIdent = ident;
        std::replace(safeIdent.begin(), safeIdent.end(), '/', '-');
        std::replace(safeIdent.begin(), safeIdent.end(), '\\', '-');
        const std::filesystem::path dir = netDb / (std::string("r") + safeIdent[0]);
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        std::ofstream out(dir / ("routerInfo-" + safeIdent + ".dat"), std::ios::binary
            | std::ios::trunc);
        if (!out) { continue; }
        out.write(reinterpret_cast<const char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size()));
        if (out) { ++written; }
    }
    return written;
}

std::optional<Privacy> privacyFromString(std::string_view text)
{
    if (text == "minimal") { return Privacy::eMinimal; }
    if (text == "middle") { return Privacy::eMiddle; }
    if (text == "max") { return Privacy::eMax; }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

struct Stream::Impl {
    std::shared_ptr<i2pd::stream::Stream> stream;
    std::atomic<bool> closed{false};
};

Stream::Stream() : impl_(std::make_unique<Impl>()) {}
Stream::~Stream() { close(); }

std::size_t Stream::readSome(void* buffer, std::size_t size)
{
    if (!impl_->stream || impl_->closed || size == 0) { return 0; }
    while (!impl_->closed)
    {
        auto promise = std::make_shared<std::promise<std::size_t>>();
        auto future = promise->get_future();
        impl_->stream->AsyncReceive(boost::asio::buffer(buffer, size),
            [promise](const boost::system::error_code&, std::size_t received)
            {
                promise->set_value(received);
            }, 5);
        const std::size_t received = future.get();
        if (received > 0) { return received; }
        if (isClosedStatus(impl_->stream->GetStatus())) { return 0; }
        // otherwise a poll timeout on a still-open stream: wait again
    }
    return 0;
}

void Stream::readExact(void* buffer, std::size_t size)
{
    auto* out = static_cast<std::uint8_t*>(buffer);
    std::size_t got = 0;
    while (got < size)
    {
        const std::size_t n = readSome(out + got, size - got);
        if (n == 0) { throw std::runtime_error("bazarish::i2p: stream EOF before readExact complete"); }
        got += n;
    }
}

void Stream::writeAll(const void* data, std::size_t size)
{
    if (!impl_->stream) { throw std::runtime_error("bazarish::i2p: write on a closed stream"); }
    const auto* in = static_cast<const std::uint8_t*>(data);
    std::size_t off = 0;
    while (off < size)
    {
        const std::size_t written = impl_->stream->Send(in + off, size - off);
        if (written == 0) { break; }
        off += written;
    }
}

std::size_t Stream::pendingBytes() const
{
    if (!impl_->stream || impl_->closed) {
        return 0;
    }
    // Two queues, not one: bytes still in the send buffer, and packets already
    // sent that the far side has not acknowledged. Counting only the first made a
    // sender's progress run far ahead of the receiver's, because the engine
    // drains the buffer into its unacknowledged window immediately. The in-flight
    // half is an upper bound (packet count times the streaming MTU), so progress
    // errs behind rather than ahead.
    return impl_->stream->GetSendBufferSize()
        + impl_->stream->GetSendQueueSize() * i2pd::stream::STREAMING_MTU;
}

void Stream::close()
{
    if (impl_->stream && !impl_->closed.exchange(true))
    {
        impl_->stream->Close();
    }
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

struct Endpoint::Impl {
    // Keeps the router's shared service alive for as long as this endpoint (and its
    // destination's reference to the io_context) exists. Declared first so it is
    // destroyed last, after dest below.
    std::shared_ptr<IoService> io;
    std::shared_ptr<i2pd::client::ClientDestination> dest;
    std::shared_ptr<i2pd::datagram::DatagramDestination> datagram;
    LeaseSetKind leaseSet = LeaseSetKind::eEncrypted;

    // What this destination is for, as the caller named it: only ever used to say
    // which one a log line is about.
    std::string label;
    std::string publicBase64;
    std::string routingHost;
    Bytes privateBlob;

    std::mutex acceptMutex;
    std::condition_variable acceptCv;
    std::deque<std::shared_ptr<i2pd::stream::Stream>> acceptQueue;

    struct Incoming {
        std::string from;
        std::vector<std::uint8_t> payload;
    };
    std::mutex dgMutex;
    std::condition_variable dgCv;
    std::deque<Incoming> dgQueue;

    std::mutex rawMutex;
    std::condition_variable rawCv;
    std::deque<std::vector<std::uint8_t>> rawQueue;

    ~Impl()
    {
        // Stop the destination first so no accept/datagram callback fires against
        // members that are about to be torn down.
        if (dest) { dest->Stop(); }
    }
};

Endpoint::Endpoint() = default;
Endpoint::~Endpoint()
{
    if (!impl_ || !impl_->dest) {
        return;
    }
    // Stop the destination on the lane that services it, holding it alive until
    // that runs. Releasing it from this thread stops it while the lane may still
    // be sending queued packets, and the streaming layer it tears down is read by
    // that very handler - a use-after-free ASAN catches in
    // Stream::SendPackets -> StreamingDestination::GetOwner().
    const std::shared_ptr<i2pd::client::ClientDestination> dest = impl_->dest;
    bazarish::log::info("i2p: closing destination {} ({})",
        impl_->label.empty() ? std::string("unnamed") : impl_->label, impl_->routingHost);
    impl_->dest.reset();
    impl_->datagram.reset();
    boost::asio::post(dest->GetService(), [dest]() { dest->Stop(); });
}

bool Endpoint::ready() const { return impl_->dest->IsReady(); }

bool Endpoint::waitReady(std::chrono::seconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!impl_->dest->IsReady())
    {
        if (std::chrono::steady_clock::now() >= deadline) { return false; }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return true;
}

std::string Endpoint::publicBase64() const { return impl_->publicBase64; }
std::string Endpoint::routingHost() const { return impl_->routingHost; }
Bytes Endpoint::privateBlob() const { return impl_->privateBlob; }

void Endpoint::refreshOfflineSignature(const Keys& newTransient)
{
    impl_->dest->UpdateOfflineSignature(newTransient.impl_->keys);
    impl_->privateBlob = newTransient.blob();
}

std::unique_ptr<Stream> Endpoint::connect(const std::string& host, std::chrono::seconds timeout)
{
    // Resolve the target once into a request issuer (b32 ident, b33 blinded key,
    // or a raw base64 destination).
    auto dest = impl_->dest;
    std::function<void(i2pd::client::StreamRequestComplete)> issue;
    if (isB32I2pHost(host))
    {
        const std::string label = host.substr(0, host.size() - kB32SuffixLen);
        std::uint8_t raw[64];
        const std::size_t n = i2pd::data::Base32ToByteStream(label, raw, sizeof raw);
        if (n == 32)
        {
            const i2pd::data::IdentHash ident(raw);
            issue = [dest, ident](i2pd::client::StreamRequestComplete cb) { dest->CreateStream(cb, ident); };
        }
        else
        {
            auto blinded = std::make_shared<i2pd::data::BlindedPublicKey>(std::string_view(label));
            issue = [dest, blinded](i2pd::client::StreamRequestComplete cb) { dest->CreateStream(cb, blinded); };
        }
    }
    else
    {
        auto identity = std::make_shared<i2pd::data::IdentityEx>();
        if (identity->FromBase64(host) == 0) { return nullptr; }
        const i2pd::data::IdentHash ident = identity->GetIdentHash();
        issue = [dest, ident](i2pd::client::StreamRequestComplete cb) { dest->CreateStream(cb, ident); };
    }

    // Retry the lookup-and-connect until the deadline: a freshly published remote
    // LeaseSet can lag the remote's readiness, so one attempt may miss it.
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
        auto promise = std::make_shared<std::promise<std::shared_ptr<i2pd::stream::Stream>>>();
        auto future = promise->get_future();
        issue([promise](std::shared_ptr<i2pd::stream::Stream> s) { promise->set_value(s); });

        const auto remaining = deadline - std::chrono::steady_clock::now();
        const auto attempt = std::min(
            std::chrono::duration_cast<std::chrono::milliseconds>(remaining),
            std::chrono::milliseconds(30000));
        if (attempt.count() <= 0) { break; }
        if (future.wait_for(attempt) == std::future_status::ready)
        {
            if (auto stream = future.get())
            {
                std::unique_ptr<Stream> wrapped(new Stream());
                wrapped->impl_->stream = std::move(stream);
                return wrapped;
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));  // failed round; re-request
        }
    }
    return nullptr;
}

std::unique_ptr<Stream> Endpoint::accept(std::string& peerBase64, std::chrono::seconds timeout)
{
    std::unique_lock<std::mutex> lock(impl_->acceptMutex);
    const auto ready = [this] { return !impl_->acceptQueue.empty(); };
    if (timeout.count() == 0)
    {
        impl_->acceptCv.wait(lock, ready);
    }
    else if (!impl_->acceptCv.wait_for(lock, timeout, ready))
    {
        return nullptr;
    }
    auto stream = impl_->acceptQueue.front();
    impl_->acceptQueue.pop_front();
    lock.unlock();

    if (stream->GetRemoteIdentity()) { peerBase64 = stream->GetRemoteIdentity()->ToBase64(); }
    std::unique_ptr<Stream> wrapped(new Stream());
    wrapped->impl_->stream = std::move(stream);
    return wrapped;
}

void Endpoint::sendDatagram(const std::string& host, const void* data, std::size_t size)
{
    if (!impl_->datagram) { return; }
    const auto* payload = static_cast<const std::uint8_t*>(data);

    if (isB32I2pHost(host))
    {
        const std::string label = host.substr(0, host.size() - kB32SuffixLen);
        std::uint8_t raw[64];
        const std::size_t n = i2pd::data::Base32ToByteStream(label, raw, sizeof raw);
        if (n == 32)
        {
            impl_->datagram->SendDatagramTo(payload, size, i2pd::data::IdentHash(raw));
        }
        else
        {
            // Encrypted-LS peer: resolve the blinded leaseset, then send (best-effort).
            auto blinded = std::make_shared<i2pd::data::BlindedPublicKey>(std::string_view(label));
            auto datagram = impl_->datagram;
            std::vector<std::uint8_t> copy(payload, payload + size);
            impl_->dest->RequestDestinationWithEncryptedLeaseSet(blinded,
                [datagram, copy](std::shared_ptr<i2pd::data::LeaseSet> ls)
                {
                    if (ls) { datagram->SendDatagramTo(copy.data(), copy.size(), ls->GetIdentHash()); }
                });
        }
    }
    else
    {
        auto identity = std::make_shared<i2pd::data::IdentityEx>();
        if (identity->FromBase64(host) > 0)
        {
            impl_->datagram->SendDatagramTo(payload, size, identity->GetIdentHash());
        }
    }
}

std::vector<std::uint8_t> Endpoint::receiveDatagram(std::string& peerBase64,
    std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(impl_->dgMutex);
    if (!impl_->dgCv.wait_for(lock, timeout, [this] { return !impl_->dgQueue.empty(); }))
    {
        return {};
    }
    auto incoming = std::move(impl_->dgQueue.front());
    impl_->dgQueue.pop_front();
    lock.unlock();
    peerBase64 = std::move(incoming.from);
    return std::move(incoming.payload);
}

void Endpoint::sendRawDatagram(const std::string& host, const void* data, std::size_t size)
{
    if (!impl_->datagram) { return; }
    const auto* payload = static_cast<const std::uint8_t*>(data);

    if (isB32I2pHost(host))
    {
        const std::string label = host.substr(0, host.size() - kB32SuffixLen);
        std::uint8_t rawHash[64];
        const std::size_t n = i2pd::data::Base32ToByteStream(label, rawHash, sizeof rawHash);
        if (n == 32)
        {
            impl_->datagram->SendRawDatagramTo(payload, size, i2pd::data::IdentHash(rawHash));
        }
        else
        {
            auto blinded = std::make_shared<i2pd::data::BlindedPublicKey>(std::string_view(label));
            auto datagram = impl_->datagram;
            std::vector<std::uint8_t> copy(payload, payload + size);
            impl_->dest->RequestDestinationWithEncryptedLeaseSet(blinded,
                [datagram, copy](std::shared_ptr<i2pd::data::LeaseSet> ls)
                {
                    if (ls) { datagram->SendRawDatagramTo(copy.data(), copy.size(), ls->GetIdentHash()); }
                });
        }
    }
    else
    {
        auto identity = std::make_shared<i2pd::data::IdentityEx>();
        if (identity->FromBase64(host) > 0)
        {
            impl_->datagram->SendRawDatagramTo(payload, size, identity->GetIdentHash());
        }
    }
}

std::vector<std::uint8_t> Endpoint::receiveRawDatagram(std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(impl_->rawMutex);
    if (!impl_->rawCv.wait_for(lock, timeout, [this] { return !impl_->rawQueue.empty(); }))
    {
        return {};
    }
    auto payload = std::move(impl_->rawQueue.front());
    impl_->rawQueue.pop_front();
    return payload;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

struct Router::Impl {
    bool owns = false;
    bool inited = false;
    bool started = false;
    std::shared_ptr<IoService> io;

    // Every destination created on this router, weakly held so an Endpoint the
    // caller dropped (a one-time dest) disappears from the status view by
    // itself. Only createEndpoint and localDestinations touch it.
    struct DestEntry {
        std::weak_ptr<i2pd::client::ClientDestination> dest;
        std::string label;
        std::string owner;
        std::string host;
        bool published = false;
    };
    mutable std::mutex destsMutex;
    std::vector<DestEntry> dests;

    ~Impl()
    {
        // Release the shared service before stopping the engine: workers must drain
        // and join while the engine they post to is still up.
        io.reset();
        if (started)
        {
            i2pd::api::StopI2P();
        }
        // The engine is initialized once per process, so terminate it (crypto) only
        // here, at the end of the object's life - never on stop(), so the network
        // can be started again. A second InitI2P is unsupported.
        if (inited)
        {
            i2pd::api::TerminateI2P();
        }
        if (owns) { g_routerLive = false; }
    }
};

Router::Router(RouterConfig config) : impl_(std::make_unique<Impl>())
{
    bool expected = false;
    if (!g_routerLive.compare_exchange_strong(expected, true))
    {
        throw std::runtime_error("bazarish::i2p::Router: only one router per process");
    }
    impl_->owns = true;

    std::vector<std::string> args;
    args.push_back("bazarish-i2p");
    args.push_back("--datadir=" + config.dataDir.string());
    if (config.role == Role::eClient)
    {
        args.push_back("--notransit");
    }
    else
    {
        args.push_back("--bandwidth=X");
        args.push_back("--share=100");
    }
    args.push_back("--loglevel=warn");
    // Peer profiles are a plain-text record of which routers this installation
    // has been talking to, and when. Keeping them buys a little tunnel-building
    // quality; leaving them on disk costs a log of the user's activity.
    args.push_back("--persist.profiles=false");
    if (!config.allowPublicReseed)
    {
        // Point the reseeder at a local file that does not exist: it then tries
        // that file, fails, and - by its own control flow - never falls through
        // to the built-in reseed servers. Exactly the intent: this router
        // bootstraps from the netDb its own server handed it, or not at all.
        args.push_back("--reseed.file=" + (config.dataDir / "no-public-reseed.su3").string());
    }

    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) { argv.push_back(arg.data()); }

    i2pd::api::InitI2P(static_cast<int>(argv.size()), argv.data(), "bazarish-i2p");
    impl_->inited = true;
    start();
}

Router::~Router() = default;

void Router::start()
{
    if (impl_->started) { return; }
    i2pd::api::StartI2P();
    // StartI2P always (re)points logging, so install our sink after it (on every
    // start - it is reset each time). The sink drops everything unless logging was
    // explicitly turned on, so by default the embedded router is silent.
    i2pd::log::Logger().SendTo([](LogLevel level, const std::string& text)
    {
        if (!g_i2pLogging.load()) { return; }
        bazarish::log::emit(mapLevel(level), text);
    });
    // Honor the current logging setting (default OFF) now that the logger exists,
    // so the engine does not even format messages while logging is suppressed.
    i2pd::log::Logger().SetLogLevel(g_i2pLogging.load() ? "warn" : "none");
    impl_->started = true;
    impl_->io = std::make_shared<IoService>(ioContextCount());
}

void Router::stop()
{
    if (!impl_->started) { return; }
    // Release the shared service before stopping the engine: workers must drain and
    // join while the engine they post to is still up.
    impl_->io.reset();
    i2pd::api::StopI2P();
    impl_->started = false;
}

bool Router::running() const { return impl_->started; }

bool Router::ready() const
{
    if (i2pd::data::netdb.GetNumRouters() == 0) { return false; }
    auto pool = i2pd::tunnel::tunnels.GetExploratoryPool();
    return pool && !pool->GetOutboundTunnels().empty();
}

bool Router::waitReady(std::chrono::seconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!ready())
    {
        if (std::chrono::steady_clock::now() >= deadline) { return false; }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return true;
}

int Router::knownRouters() const { return i2pd::data::netdb.GetNumRouters(); }
int Router::floodfills() const { return i2pd::data::netdb.GetNumFloodfills(); }
int Router::transitTunnels() const
{
    return static_cast<int>(i2pd::tunnel::tunnels.CountTransitTunnels());
}
int Router::inboundTunnels() const
{
    return static_cast<int>(i2pd::tunnel::tunnels.CountInboundTunnels());
}
int Router::outboundTunnels() const
{
    return static_cast<int>(i2pd::tunnel::tunnels.CountOutboundTunnels());
}

std::vector<TransportPeer> Router::transportPeers() const
{
    std::vector<TransportPeer> peers;
    // Copy each server's session map (the i2pd webconsole pattern) so iteration
    // is over a snapshot rather than the live, concurrently-mutated container.
    const auto collect = [&peers](const auto& sessions, const char* name) {
        for (const auto& entry : sessions) {
            const auto& session = entry.second;
            if (!session || !session->IsEstablished()) { continue; }
            const auto remote = session->GetRemoteIdentity();
            if (!remote) { continue; }  // handshake not finished yet
            TransportPeer peer;
            peer.ident = remote->GetIdentHash().ToBase64().substr(0, 8);
            peer.transport = name;
            peer.outbound = session->IsOutgoing();
            // Remote socket address; IPv6 is bracketed so the port stays readable.
            const auto endpoint = session->GetRemoteEndpoint();
            const auto address = endpoint.address();
            const std::string host = address.to_string();
            peer.endpoint = address.is_v6() ? ("[" + host + "]:" + std::to_string(endpoint.port()))
                                            : (host + ":" + std::to_string(endpoint.port()));
            peers.push_back(std::move(peer));
        }
    };
    if (const auto* const ntcp2 = i2pd::transport::transports.GetNTCP2Server()) {
        const auto sessions = ntcp2->GetNTCP2Sessions();
        collect(sessions, "NTCP2");
    }
    if (const auto* const ssu2 = i2pd::transport::transports.GetSSU2Server()) {
        const auto sessions = ssu2->GetSSU2Sessions();
        collect(sessions, "SSU2");
    }
    return peers;
}

void setI2pLogging(bool enabled)
{
    g_i2pLogging.store(enabled);
    // Also adjust the engine's own minimum level so it does not waste work
    // formatting messages the sink would drop. The sink gate above is the
    // authoritative on/off; this is just an optimization and is safe any time.
    i2pd::log::Logger().SetLogLevel(enabled ? "warn" : "none");
}

bool i2pLogging()
{
    return g_i2pLogging.load();
}

void Router::retagEndpoint(const Endpoint& endpoint, std::string label, std::string owner)
{
    const std::shared_ptr<i2pd::client::ClientDestination> dest = endpoint.impl_->dest;
    std::lock_guard<std::mutex> lock(impl_->destsMutex);
    for (Impl::DestEntry& entry : impl_->dests) {
        if (entry.dest.lock() == dest) {
            entry.label = std::move(label);
            entry.owner = std::move(owner);
            return;
        }
    }
}

std::vector<LocalDestination> Router::localDestinations() const
{
    // More than any pool can hold: the quantity is clamped to 16 per direction,
    // so this asks for every established inbound tunnel there can be.
    constexpr int kTunnelCountProbe = 64;
    std::vector<LocalDestination> live;
    std::lock_guard<std::mutex> lock(impl_->destsMutex);
    std::erase_if(impl_->dests, [](const Impl::DestEntry& entry) { return entry.dest.expired(); });
    for (const Impl::DestEntry& entry : impl_->dests) {
        const std::shared_ptr<i2pd::client::ClientDestination> dest = entry.dest.lock();
        if (!dest) { continue; }
        LocalDestination info;
        info.label = entry.label;
        info.owner = entry.owner;
        info.host = entry.host;
        info.published = entry.published;
        info.ready = dest->IsReady();
        info.remoteLeaseSets = dest->GetNumRemoteLeaseSets();
        // A stopped destination keeps its pool until the last handler holding it
        // returns, and the pool stands down the moment it is stopped: that flag is
        // the difference between an address coming up and one going away.
        const auto tunnelPool = dest->GetTunnelPool();
        info.closing = !tunnelPool || !tunnelPool->IsActive();
        if (const auto pool = tunnelPool) {
            info.inboundTunnels = static_cast<int>(pool->GetInboundTunnels(kTunnelCountProbe).size());
            // No locked accessor exists for the outbound set: copy it the way the
            // engine's own status console does, then count what is established.
            const auto outbound = pool->GetOutboundTunnels();
            for (const auto& tunnel : outbound) {
                if (tunnel && tunnel->IsEstablished()) {
                    ++info.outboundTunnels;
                }
            }
        }
        live.push_back(std::move(info));
    }
    return live;
}

std::shared_ptr<Endpoint> Router::createEndpoint(const EndpointConfig& config)
{
    auto impl = std::make_unique<Endpoint::Impl>();
    impl->label = config.label;
    impl->leaseSet = config.leaseSet;
    impl->publicBase64 = config.keys.publicBase64();
    impl->routingHost = bazarish::i2p::routingHost(impl->publicBase64, config.leaseSet);
    impl->privateBlob = config.keys.blob();

    i2pd::util::Mapping params;
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_TYPE,
        config.leaseSet == LeaseSetKind::eEncrypted ? "5" : "3");
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_ENCRYPTION_TYPE, "4");
    // Never write this destination's leaseset keys to the router directory: the
    // files there are named by the destination, so persisting them would leave a
    // list of every address this installation has served lying in the clear. The
    // address itself is unaffected - only the leaseset's encryption key is new
    // after a restart, and subscribers fetch the current leaseset anyway.
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_PERSIST_KEYS, "false");
    int length = 0;
    int variance = 0;
    privacyToTunnel(config.privacy, length, variance);
    params.Insert(i2pd::client::I2CP_PARAM_INBOUND_TUNNEL_LENGTH, std::to_string(length));
    params.Insert(i2pd::client::I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH, std::to_string(length));
    params.Insert(i2pd::client::I2CP_PARAM_INBOUND_TUNNELS_LENGTH_VARIANCE, std::to_string(variance));
    params.Insert(i2pd::client::I2CP_PARAM_OUTBOUND_TUNNELS_LENGTH_VARIANCE, std::to_string(variance));
    const int quantity = std::clamp(config.tunnelQuantity, 1, 16);
    params.Insert(i2pd::client::I2CP_PARAM_INBOUND_TUNNELS_QUANTITY, std::to_string(quantity));
    params.Insert(i2pd::client::I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY, std::to_string(quantity));

    // Pin this destination to one lane of the router's io_context pool rather than
    // a dedicated thread, so the router scales to many destinations on a fixed pool
    // while every handler of this destination stays on a single thread.
    impl->io = impl_->io;
    impl->dest = std::make_shared<i2pd::client::ClientDestination>(
        impl->io->next(), config.keys.impl_->keys, config.published, &params);
    impl->dest->Start();
    {
        std::lock_guard<std::mutex> lock(impl_->destsMutex);
        std::erase_if(impl_->dests,
            [](const Impl::DestEntry& entry) { return entry.dest.expired(); });
        impl_->dests.push_back(Impl::DestEntry{
            impl->dest, config.label, config.owner, impl->routingHost, config.published});
    }

    auto* raw = impl.get();
    impl->dest->AcceptStreams([raw](std::shared_ptr<i2pd::stream::Stream> stream)
    {
        if (!stream) { return; }
        {
            std::lock_guard<std::mutex> lock(raw->acceptMutex);
            raw->acceptQueue.push_back(std::move(stream));
        }
        raw->acceptCv.notify_one();
    });

    impl->datagram = impl->dest->CreateDatagramDestination();
    impl->datagram->SetReceiver([raw](const i2pd::data::IdentityEx& from, std::uint16_t, std::uint16_t,
        const std::uint8_t* buf, std::size_t len, const i2pd::util::Mapping*)
    {
        Endpoint::Impl::Incoming incoming;
        incoming.from = from.ToBase64();
        incoming.payload.assign(buf, buf + len);
        {
            std::lock_guard<std::mutex> lock(raw->dgMutex);
            raw->dgQueue.push_back(std::move(incoming));
        }
        raw->dgCv.notify_one();
    });
    impl->datagram->SetRawReceiver([raw](std::uint16_t, std::uint16_t,
        const std::uint8_t* buf, std::size_t len)
    {
        {
            std::lock_guard<std::mutex> lock(raw->rawMutex);
            raw->rawQueue.emplace_back(buf, buf + len);
        }
        raw->rawCv.notify_one();
    });

    std::shared_ptr<Endpoint> endpoint(new Endpoint());
    endpoint->impl_ = std::move(impl);
    return endpoint;
}

}  // namespace bazarish::i2p
