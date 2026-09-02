// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "I2pBackend.hpp"

#include "bazarish/Crypto.hpp"
#include "bazarish/I2pAddress.hpp"

#include <algorithm>
#include <atomic>
#include <stdexcept>
#include <thread>

namespace bazarish::i2p {

namespace {

// How often readiness is re-checked while waiting for it. A destination comes up
// in seconds and the router in minutes, so they are not asked at the same rate.
constexpr auto kEndpointReadyPoll = std::chrono::milliseconds(200);
constexpr auto kRouterReadyPoll = std::chrono::milliseconds(500);

// The two fixed-size private fields that follow the identity in a private-keys
// blob, for the only key types this project uses: ElGamal encryption and an
// Ed25519 signature.
constexpr std::size_t kElGamalPrivateKeyBytes = 256;
constexpr std::size_t kEd25519PrivateKeyBytes = 32;

// libi2pd log output gate. OFF by default: the engine's logging is suppressed
// until a caller turns it on, and a build with no engine keeps the flag anyway
// so callers need not care which transport they got.
std::atomic<bool> g_i2pLogging{false};

#ifndef BAZARISH_WITH_I2PD
[[noreturn]] void noEmbeddedEngine()
{
    throw std::runtime_error(
        "bazarish::i2p: this build carries no embedded engine; the router is external");
}
#endif

}  // namespace

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

// Key material is held as the blob it is stored and transmitted as, and read
// with this project's own parser. Only minting a destination and delegating a
// transient need the engine, which is why they are the two calls a build
// without it cannot serve.
struct Keys::Impl {
    Bytes blob;
};

Keys::Keys() : impl_(std::make_unique<Impl>()) {}
Keys::Keys(const Keys& other) : impl_(std::make_unique<Impl>(*other.impl_)) {}
Keys::Keys(Keys&&) noexcept = default;
Keys& Keys::operator=(const Keys& other)
{
    impl_ = std::make_unique<Impl>(*other.impl_);
    return *this;
}
Keys& Keys::operator=(Keys&&) noexcept = default;
Keys::~Keys() = default;

Keys Keys::generate()
{
#ifdef BAZARISH_WITH_I2PD
    return fromBlob(backend::generateKeysBlob());
#else
    noEmbeddedEngine();
#endif
}

Keys Keys::fromBlob(const Bytes& blob)
{
    Keys keys;
    // Reading the identity is what rejects a blob that is not one.
    (void)i2pIdentityLength(blob);
    keys.impl_->blob = blob;
    return keys;
}

Bytes Keys::blob() const
{
    return impl_->blob;
}

std::string Keys::privateBase64() const
{
    return standardToI2pBase64(toBase64(impl_->blob));
}

std::string Keys::publicBase64() const
{
    const std::size_t identity = i2pIdentityLength(impl_->blob);
    return standardToI2pBase64(
        toBase64(Bytes(impl_->blob.begin(), impl_->blob.begin() + identity)));
}

std::string Keys::base32() const
{
    const std::size_t identity = i2pIdentityLength(impl_->blob);
    return toBase32(sha256(Bytes(impl_->blob.begin(), impl_->blob.begin() + identity)));
}

bool Keys::isOffline() const
{
    const std::size_t signingAt = i2pIdentityLength(impl_->blob) + kElGamalPrivateKeyBytes;
    if (impl_->blob.size() < signingAt + kEd25519PrivateKeyBytes) {
        throw std::runtime_error("bazarish::i2p: truncated private keys blob");
    }
    // A delegated blob carries the transient after a zeroed signing key: the
    // master's own signing key is exactly what offline delegation withholds.
    return std::all_of(impl_->blob.begin() + signingAt,
        impl_->blob.begin() + signingAt + kEd25519PrivateKeyBytes,
        [](const std::uint8_t byte) { return byte == 0; });
}

Keys Keys::issueTransient(const std::int64_t expiresUnix) const
{
#ifdef BAZARISH_WITH_I2PD
    return fromBlob(backend::issueTransientBlob(impl_->blob, expiresUnix));
#else
    (void)expiresUnix;
    noEmbeddedEngine();
#endif
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

std::string routerVersion()
{
#ifdef BAZARISH_WITH_I2PD
    return backend::embeddedRouterVersion();
#else
    // Nothing to name: the router this build talks to is somebody else's
    // process, and SAM does not say what version it is.
    return {};
#endif
}

std::vector<Bytes> sampleRouterInfos(const std::size_t count)
{
#ifdef BAZARISH_WITH_I2PD
    return backend::embeddedSampleRouterInfos(count);
#else
    (void)count;
    noEmbeddedEngine();
#endif
}

std::size_t seedRouterInfos(const std::filesystem::path& dataDir, const std::vector<Bytes>& routers)
{
#ifdef BAZARISH_WITH_I2PD
    return backend::embeddedSeedRouterInfos(dataDir, routers);
#else
    (void)dataDir;
    (void)routers;
    noEmbeddedEngine();
#endif
}

std::optional<Privacy> privacyFromString(const std::string_view text)
{
    if (text == "minimal") {
        return Privacy::eMinimal;
    }
    if (text == "middle") {
        return Privacy::eMiddle;
    }
    if (text == "max") {
        return Privacy::eMax;
    }
    return std::nullopt;
}

std::string_view privacyName(const Privacy privacy)
{
    switch (privacy) {
        case Privacy::eMinimal: return "minimal";
        case Privacy::eMiddle: return "middle";
        case Privacy::eMax: return "max";
    }
    return "max";
}

void setI2pLogging(const bool enabled)
{
    g_i2pLogging = enabled;
}

bool i2pLogging()
{
    return g_i2pLogging;
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

struct Stream::Impl {
    std::unique_ptr<backend::StreamBackend> transport;
};

Stream::Stream() : impl_(std::make_unique<Impl>()) {}
Stream::~Stream() = default;

void Stream::setReadTimeout(const std::chrono::seconds timeout)
{
    impl_->transport->setReadTimeout(timeout);
}

std::size_t Stream::readSome(void* buffer, const std::size_t size)
{
    return impl_->transport->readSome(buffer, size);
}

void Stream::readExact(void* buffer, const std::size_t size)
{
    auto* cursor = static_cast<std::uint8_t*>(buffer);
    std::size_t read = 0;
    while (read < size) {
        const std::size_t got = impl_->transport->readSome(cursor + read, size - read);
        if (got == 0) {
            throw std::runtime_error("bazarish::i2p: stream closed before the read completed");
        }
        read += got;
    }
}

void Stream::writeAll(const void* data, const std::size_t size)
{
    impl_->transport->writeAll(data, size);
}

std::size_t Stream::pendingBytes() const
{
    return impl_->transport->pendingBytes();
}

void Stream::close()
{
    impl_->transport->close();
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

struct Endpoint::Impl {
    std::shared_ptr<backend::EndpointBackend> transport;
};

Endpoint::Endpoint() : impl_(std::make_unique<Impl>()) {}
Endpoint::~Endpoint() = default;

bool Endpoint::ready() const
{
    return impl_->transport->ready();
}

bool Endpoint::waitReady(const std::chrono::seconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (ready()) {
            return true;
        }
        std::this_thread::sleep_for(kEndpointReadyPoll);
    }
    return ready();
}

std::string Endpoint::publicBase64() const
{
    return impl_->transport->publicBase64();
}

std::string Endpoint::routingHost() const
{
    return impl_->transport->routingHost();
}

Bytes Endpoint::privateBlob() const
{
    return impl_->transport->privateBlob();
}

void Endpoint::refreshOfflineSignature(const Keys& newTransient)
{
    impl_->transport->refreshOfflineSignature(newTransient);
}

// A Stream is minted by an Endpoint and by nothing else, which is why the two
// dialling paths wrap it here rather than through a helper that would need the
// same access.
std::unique_ptr<Stream> Endpoint::connect(
    const std::string& host, const std::chrono::seconds timeout)
{
    std::unique_ptr<backend::StreamBackend> transport = impl_->transport->connect(host, timeout);
    if (!transport) {
        return nullptr;
    }
    std::unique_ptr<Stream> stream(new Stream());
    stream->impl_->transport = std::move(transport);
    return stream;
}

std::unique_ptr<Stream> Endpoint::accept(
    std::string& peerBase64, const std::chrono::seconds timeout)
{
    std::unique_ptr<backend::StreamBackend> transport
        = impl_->transport->accept(peerBase64, timeout);
    if (!transport) {
        return nullptr;
    }
    std::unique_ptr<Stream> stream(new Stream());
    stream->impl_->transport = std::move(transport);
    return stream;
}

void Endpoint::sendDatagram(const std::string& host, const void* data, const std::size_t size)
{
    impl_->transport->sendDatagram(host, data, size);
}

std::vector<std::uint8_t> Endpoint::receiveDatagram(
    std::string& peerBase64, const std::chrono::milliseconds timeout)
{
    return impl_->transport->receiveDatagram(peerBase64, timeout);
}

void Endpoint::sendRawDatagram(const std::string& host, const void* data, const std::size_t size)
{
    impl_->transport->sendRawDatagram(host, data, size);
}

std::vector<std::uint8_t> Endpoint::receiveRawDatagram(const std::chrono::milliseconds timeout)
{
    return impl_->transport->receiveRawDatagram(timeout);
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

struct Router::Impl {
    std::unique_ptr<backend::RouterBackend> transport;
};

Router::Router(RouterConfig config) : impl_(std::make_unique<Impl>())
{
    if (config.backend == Backend::eSam) {
        impl_->transport = backend::makeSamRouter(config);
        return;
    }
#ifdef BAZARISH_WITH_I2PD
    impl_->transport = backend::makeEmbeddedRouter(config);
#else
    noEmbeddedEngine();
#endif
}

Router::~Router() = default;

Capabilities Router::capabilities() const
{
    return impl_->transport->capabilities();
}

void Router::start()
{
    impl_->transport->start();
}

void Router::stop()
{
    impl_->transport->stop();
}

bool Router::running() const
{
    return impl_->transport->running();
}

bool Router::ready() const
{
    return impl_->transport->ready();
}

bool Router::waitReady(const std::chrono::seconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (ready()) {
            return true;
        }
        std::this_thread::sleep_for(kRouterReadyPoll);
    }
    return ready();
}

int Router::knownRouters() const
{
    return impl_->transport->knownRouters();
}

int Router::floodfills() const
{
    return impl_->transport->floodfills();
}

int Router::transitTunnels() const
{
    return impl_->transport->transitTunnels();
}

int Router::inboundTunnels() const
{
    return impl_->transport->inboundTunnels();
}

int Router::outboundTunnels() const
{
    return impl_->transport->outboundTunnels();
}

std::vector<TransportPeer> Router::transportPeers() const
{
    return impl_->transport->transportPeers();
}

std::vector<LocalDestination> Router::localDestinations() const
{
    return impl_->transport->localDestinations();
}

void Router::setSocksProxy(const std::string& host, const int port)
{
    impl_->transport->setSocksProxy(host, port);
}

ProxyState Router::proxyState() const
{
    return impl_->transport->proxyState();
}

Keys Router::generateKeys()
{
    return impl_->transport->generateKeys();
}

std::shared_ptr<Endpoint> Router::createEndpoint(const EndpointConfig& config)
{
    std::shared_ptr<Endpoint> endpoint(new Endpoint());
    endpoint->impl_->transport = impl_->transport->createEndpoint(config);
    return endpoint;
}

void Router::retagEndpoint(const Endpoint& endpoint, std::string label, std::string owner)
{
    impl_->transport->retagEndpoint(
        *endpoint.impl_->transport, std::move(label), std::move(owner));
}

}  // namespace bazarish::i2p
