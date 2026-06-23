// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "bazarish/I2pAddress.hpp"
#include "bazarish/Log.hpp"

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
#include "Streaming.h"
#include "Tunnel.h"
#include "TunnelPool.h"
#include "util.h"

#include <algorithm>
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
        case Privacy::eMax:     length = 2; variance = 1; break;
    }
}

bool isClosedStatus(i2pd::stream::StreamStatus status)
{
    return status == i2pd::stream::eStreamStatusReset
        || status == i2pd::stream::eStreamStatusClosed
        || status == i2pd::stream::eStreamStatusTerminated;
}

// One embedded router per process (the i2pd engine is process-global).
std::atomic<bool> g_routerLive{false};

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
    std::shared_ptr<i2pd::client::RunnableClientDestination> dest;
    std::shared_ptr<i2pd::datagram::DatagramDestination> datagram;
    LeaseSetKind leaseSet = LeaseSetKind::eEncrypted;

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

    ~Impl()
    {
        // Stop the destination first so no accept/datagram callback fires against
        // members that are about to be torn down.
        if (dest) { dest->Stop(); }
    }
};

Endpoint::Endpoint() = default;
Endpoint::~Endpoint() = default;

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

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

struct Router::Impl {
    bool owns = false;
    bool started = false;

    ~Impl()
    {
        if (started)
        {
            i2pd::api::StopI2P();
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

    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) { argv.push_back(arg.data()); }

    i2pd::api::InitI2P(static_cast<int>(argv.size()), argv.data(), "bazarish-i2p");
    i2pd::api::StartI2P();
    // StartI2P always (re)points logging, so install our sink after it.
    i2pd::log::Logger().SendTo([](LogLevel level, const std::string& text)
    {
        bazarish::log::emit(mapLevel(level), text);
    });
    impl_->started = true;
}

Router::~Router() = default;

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
int Router::transitTunnels() const { return i2pd::tunnel::tunnels.CountTransitTunnels(); }

std::shared_ptr<Endpoint> Router::createEndpoint(const EndpointConfig& config)
{
    auto impl = std::make_unique<Endpoint::Impl>();
    impl->leaseSet = config.leaseSet;
    impl->publicBase64 = config.keys.publicBase64();
    impl->routingHost = bazarish::i2p::routingHost(impl->publicBase64, config.leaseSet);
    impl->privateBlob = config.keys.blob();

    i2pd::util::Mapping params;
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_TYPE,
        config.leaseSet == LeaseSetKind::eEncrypted ? "5" : "3");
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_ENCRYPTION_TYPE, "4");
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

    impl->dest = std::make_shared<i2pd::client::RunnableClientDestination>(
        config.keys.impl_->keys, config.published, &params);
    impl->dest->Start();

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

    std::shared_ptr<Endpoint> endpoint(new Endpoint());
    endpoint->impl_ = std::move(impl);
    return endpoint;
}

}  // namespace bazarish::i2p
