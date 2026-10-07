// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "I2pBackend.hpp"

#include "bazarish/Crypto.hpp"
#include "bazarish/I2pAddress.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <stdexcept>
#include <thread>

namespace bazarish::i2p {

namespace {

constexpr auto kEndpointReadyPoll = std::chrono::milliseconds(200);
constexpr auto kRouterReadyPoll = std::chrono::milliseconds(500);

constexpr std::size_t kElGamalPrivateKeyBytes = 256;
constexpr std::size_t kEd25519PrivateKeyBytes = 32;
// The expiry that opens an offline signature block, big-endian unix seconds.
constexpr std::size_t kOfflineExpiresBytes = 4;

std::atomic<bool> g_i2pLogging{false};

}  // namespace

struct Keys::Impl {
    ~Impl()
    {
        if (!blob.empty()) {
            OPENSSL_cleanse(blob.data(), blob.size());
        }
    }

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
    return fromBlob(backend::generateKeysBlob());
}

Keys Keys::fromBlob(const Bytes& blob)
{
    Keys keys;
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

bool Keys::isOffline() const
{
    const std::size_t signingAt = i2pIdentityLength(impl_->blob) + kElGamalPrivateKeyBytes;
    if (impl_->blob.size() < signingAt + kEd25519PrivateKeyBytes) {
        throw std::runtime_error("bazarish::i2p: truncated private keys blob");
    }
    return std::all_of(impl_->blob.begin() + signingAt,
        impl_->blob.begin() + signingAt + kEd25519PrivateKeyBytes,
        [](const std::uint8_t byte) { return byte == 0; });
}

std::int64_t Keys::transientExpires() const
{
    if (!isOffline()) { return 0; }
    const std::size_t expiresAt
        = i2pIdentityLength(impl_->blob) + kElGamalPrivateKeyBytes + kEd25519PrivateKeyBytes;
    if (impl_->blob.size() < expiresAt + kOfflineExpiresBytes) {
        throw std::runtime_error("bazarish::i2p: truncated private keys blob");
    }
    std::int64_t expires = 0;
    for (std::size_t i = 0; i < kOfflineExpiresBytes; ++i) {
        expires = (expires << 8) | impl_->blob[expiresAt + i];
    }
    return expires;
}

int Keys::b33OfflineKeyDays() const
{
    return backend::b33OfflineKeyDays(impl_->blob);
}

Keys Keys::issueTransient(const int days) const
{
    return fromBlob(backend::issueTransientBlob(impl_->blob, days));
}

std::string routerVersion()
{
    return backend::embeddedRouterVersion();
}

std::vector<Bytes> sampleRouterInfos(const std::size_t count)
{
    return backend::embeddedSampleRouterInfos(count);
}

std::size_t seedRouterInfos(const std::filesystem::path& dataDir, const std::vector<Bytes>& routers)
{
    return backend::embeddedSeedRouterInfos(dataDir, routers);
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

struct Endpoint::Impl {
    std::shared_ptr<backend::EndpointBackend> transport;
};

Endpoint::Endpoint() : impl_(std::make_unique<Impl>()) {}
Endpoint::~Endpoint() = default;

bool Endpoint::ready() const
{
    return impl_->transport->ready();
}

bool Endpoint::lost() const
{
    return impl_->transport->lost();
}

bool Endpoint::waitReady(const std::chrono::seconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (ready()) {
            return true;
        }
        if (lost()) {
            return false;
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

void Endpoint::stop()
{
    impl_->transport->stop();
}

void Endpoint::refreshOfflineSignature(const Keys& newTransient)
{
    impl_->transport->refreshOfflineSignature(newTransient);
}

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

struct Router::Impl {
    std::unique_ptr<backend::RouterBackend> transport;
};

Router::Router(RouterConfig config) : impl_(std::make_unique<Impl>())
{
    if (config.backend == Backend::eSam) {
        impl_->transport = backend::makeSamRouter(config);
        return;
    }
    if (config.backend == Backend::eGateway) {
        impl_->transport = backend::makeGatewayRouter(config);
        return;
    }
    impl_->transport = backend::makeEmbeddedRouter(config);
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

void Router::setReseedUrls(const std::vector<std::string>& urls)
{
    impl_->transport->setReseedUrls(urls);
}

ReseedState Router::reseedState() const
{
    return impl_->transport->reseedState();
}

ProxyState Router::proxyState() const
{
    return impl_->transport->proxyState();
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
