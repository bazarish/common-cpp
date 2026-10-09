// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "I2pBackend.hpp"

#include "bazarish/I2pAddress.hpp"
#include "bazarish/Log.hpp"

#include <utility>

#include <boost/asio.hpp>

#include "api.h"
#include "Base.h"
#include "Blinding.h"
#include "Config.h"
#include "Crypto.h"
#include "Datagram.h"
#include "Destination.h"
#include "I2PEndian.h"
#include "Identity.h"
#include "Log.h"
#include "NetDb.hpp"
#include "RouterInfo.h"
#include "NTCP2.h"
#include "SSU2.h"
#include "Streaming.h"
#include "Transports.h"
#include "Timestamp.h"
#include "Tunnel.h"
#include "TunnelPool.h"
#include "util.h"
#include "version.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <memory>
#include <map>
#include <set>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// Reach the embedded i2pd engine.
namespace i2pd = ::i2p;

namespace bazarish::i2p {
namespace {

constexpr i2pd::data::SigningKeyType kSigType = i2pd::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519;
constexpr i2pd::data::SigningKeyType kB33SigType
    = i2pd::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519;
constexpr int kMaxB33Days = 0xFFFF;
constexpr std::size_t kB32SuffixLen = 8;
constexpr int kReceivePollSeconds = 5;
constexpr int kSessionSnapshotSeconds = 2;
constexpr int kDialRoundMillis = 30000;
constexpr int kDialSliceMillis = 250;
constexpr int kDialRetryPauseMillis = 2000;

// libi2pd's crypto state must be initialised once before any key operation.
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

std::uint64_t currentMidnight()
{
    return (i2pd::util::GetSecondsSinceEpoch()/i2pd::data::SECONDS_PER_DAY)
        * i2pd::data::SECONDS_PER_DAY;
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

Bytes createB33OfflineKeys(
    const i2pd::data::PrivateKeys& master, const int days, const std::uint64_t midnight)
{
    if (days < 1 || days > kMaxB33Days)
    {
        throw std::runtime_error("bazarish::i2p: a delegation is 1.."
            + std::to_string(kMaxB33Days) + " days");
    }
    if (master.IsOfflineSignature())
    {
        throw std::runtime_error("bazarish::i2p: only the destination's own key can delegate");
    }
    const auto identity = master.GetPublic();
    i2pd::data::BlindedPublicKey blinded(identity);
    if (!blinded.IsValid())
    {
        throw std::runtime_error("bazarish::i2p: destination has no blinded address");
    }
    const std::unique_ptr<i2pd::crypto::Verifier> transientVerifier(
        i2pd::data::IdentityEx::CreateVerifier(kB33SigType));
    const std::unique_ptr<i2pd::crypto::Verifier> blindedVerifier(
        i2pd::data::IdentityEx::CreateVerifier(blinded.GetBlindedSigType()));
    if (!transientVerifier || !blindedVerifier)
    {
        throw std::runtime_error("bazarish::i2p: unsupported blinded signature type");
    }
    const std::size_t signedLen
        = i2pd::data::OFFLINE_SIGNATURE_HEADER_LENGTH + transientVerifier->GetPublicKeyLen();
    const std::size_t keyLen
        = signedLen + blindedVerifier->GetSignatureLen() + transientVerifier->GetPrivateKeyLen();

    Bytes batch(
        i2pd::data::B33_OFFLINE_KEYS_HEADER_LENGTH + static_cast<std::size_t>(days)*keyLen);
    std::size_t offset = 0;
    batch[offset] = i2pd::data::B33_OFFLINE_KEYS_VERSION;
    offset += 1;
    std::memcpy(batch.data() + offset, identity->GetIdentHash(), i2pd::data::IdentHash::len);
    offset += i2pd::data::IdentHash::len;
    htobe16buf(batch.data() + offset, static_cast<std::uint16_t>(days));
    offset += 2;

    for (int day = 0; day < days; ++day)
    {
        char date[9];
        i2pd::util::GetDateString(midnight + day*i2pd::data::SECONDS_PER_DAY, date);
        std::uint8_t* const entry = batch.data() + offset;
        htobe32buf(entry, midnight + (day + 1)*i2pd::data::SECONDS_PER_DAY);
        htobe16buf(entry + 4, kB33SigType);
        std::uint8_t blindedPrivate[i2pd::crypto::EDDSA25519_PRIVATE_KEY_LENGTH];
        std::uint8_t blindedPublic[i2pd::crypto::EDDSA25519_PUBLIC_KEY_LENGTH];
        if (!blinded.BlindPrivateKey(
                master.GetSigningPrivateKey(), date, blindedPrivate, blindedPublic))
        {
            throw std::runtime_error("bazarish::i2p: cannot blind the signing key");
        }
        const std::unique_ptr<i2pd::crypto::Signer> signer(
            i2pd::data::PrivateKeys::CreateSigner(blinded.GetBlindedSigType(), blindedPrivate));
        OPENSSL_cleanse(blindedPrivate, sizeof blindedPrivate);
        if (!signer)
        {
            throw std::runtime_error("bazarish::i2p: cannot sign for the blinded key");
        }
        i2pd::data::PrivateKeys::GenerateSigningKeyPair(kB33SigType,
            entry + signedLen + blindedVerifier->GetSignatureLen(),
            entry + i2pd::data::OFFLINE_SIGNATURE_HEADER_LENGTH);
        signer->Sign(entry, static_cast<int>(signedLen), entry + signedLen);
        offset += keyLen;
    }
    return batch;
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
        for (auto& lane : lanes_)
        {
            Lane* const l = lane.get();
            l->worker = std::thread([l]
            {
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

    boost::asio::io_context& next()
    {
        if (lanes_.size() == 1) {
            return lanes_.front()->ctx;
        }
        const std::size_t i
            = 1 + nextLane_.fetch_add(1, std::memory_order_relaxed) % (lanes_.size() - 1);
        return lanes_[i]->ctx;
    }

    boost::asio::io_context& reserved()
    {
        return lanes_.front()->ctx;
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

std::size_t ioContextCount()
{
    const unsigned hw = std::thread::hardware_concurrency();
    const std::size_t half = hw ? hw / 2 : 2;
    return std::clamp<std::size_t>(half, 2, 8);
}

// One embedded router per process (the i2pd engine is process-global).
std::atomic<bool> g_routerLive{false};

}  // namespace

std::string backend::embeddedRouterVersion()
{
    // The upstream i2pd version baked into the embedded engine (e.g.
    return I2PD_VERSION;
}

std::vector<Bytes> backend::embeddedSampleRouterInfos(const std::size_t count)
{
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

std::size_t backend::embeddedSeedRouterInfos(
    const std::filesystem::path& dataDir, const std::vector<Bytes>& routers)
{
    ensureCryptoInit();
    const std::filesystem::path netDb = dataDir / "netDb";
    std::size_t written = 0;
    for (const Bytes& buffer : routers)
    {
        if (buffer.empty()) { continue; }
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

class EmbeddedStream final : public backend::StreamBackend {
public:
    ~EmbeddedStream() override { close(); }

    void setReadTimeout(const std::chrono::seconds timeout) override
    {
        readTimeoutSeconds = static_cast<int>(timeout.count());
    }
    std::size_t readSome(void* buffer, std::size_t size) override;
    void writeAll(const void* data, std::size_t size) override;
    std::size_t pendingBytes() const override;
    void close() override;

    std::shared_ptr<i2pd::stream::Stream> stream;
    std::shared_ptr<i2pd::client::ClientDestination> owner;
    std::shared_ptr<std::atomic<bool>> stopped;
    std::atomic<bool> closed{false};
    std::atomic<int> readTimeoutSeconds{0};
};

std::size_t EmbeddedStream::readSome(void* buffer, std::size_t size)
{
    if (!stream || closed || (stopped && *stopped) || size == 0) { return 0; }
    const std::chrono::seconds timeout{readTimeoutSeconds.load()};
    const auto started = std::chrono::steady_clock::now();
    while (!closed && !(stopped && *stopped))
    {
        auto promise = std::make_shared<std::promise<std::size_t>>();
        auto future = promise->get_future();
        stream->AsyncReceive(boost::asio::buffer(buffer, size),
            [promise](const boost::system::error_code&, std::size_t received)
            {
                promise->set_value(received);
            }, kReceivePollSeconds);
        const std::size_t received = future.get();
        if (received > 0) { return received; }
        if (isClosedStatus(stream->GetStatus())) { return 0; }
        if (timeout.count() > 0 && std::chrono::steady_clock::now() - started >= timeout)
        {
            throw std::runtime_error("bazarish::i2p: nothing read within "
                + std::to_string(timeout.count()) + "s");
        }
    }
    return 0;
}

void EmbeddedStream::writeAll(const void* data, std::size_t size)
{
    if (!stream) { throw std::runtime_error("bazarish::i2p: write on a closed stream"); }
    const auto* in = static_cast<const std::uint8_t*>(data);
    std::size_t off = 0;
    while (off < size)
    {
        const std::size_t written = stream->Send(in + off, size - off);
        if (written == 0) { break; }
        off += written;
    }
}

std::size_t EmbeddedStream::pendingBytes() const
{
    if (!stream || closed) {
        return 0;
    }
    return stream->GetSendBufferSize()
        + stream->GetSendQueueSize() * i2pd::stream::STREAMING_MTU;
}

void EmbeddedStream::close()
{
    if (stream && !closed.exchange(true))
    {
        stream->AsyncClose();
    }
}

class EmbeddedEndpoint final : public backend::EndpointBackend,
                               public std::enable_shared_from_this<EmbeddedEndpoint> {
public:
    ~EmbeddedEndpoint() override;

    bool ready() const override;
    std::string publicBase64() const override;
    std::string routingHost() const override;
    Bytes privateBlob() const override;
    void refreshOfflineSignature(const Keys& newTransient) override;
    std::unique_ptr<backend::StreamBackend> connect(
        const std::string& host, std::chrono::seconds timeout) override;
    std::unique_ptr<backend::StreamBackend> accept(
        std::string& peerBase64, std::chrono::seconds timeout) override;
    void sendDatagram(const std::string& host, const void* data, std::size_t size) override;
    std::vector<std::uint8_t> receiveDatagram(
        std::string& peerBase64, std::chrono::milliseconds timeout) override;
    void sendRawDatagram(const std::string& host, const void* data, std::size_t size) override;
    std::vector<std::uint8_t> receiveRawDatagram(std::chrono::milliseconds timeout) override;
    void stop() override;

    std::shared_ptr<std::atomic<bool>> stopped = std::make_shared<std::atomic<bool>>(false);

    std::shared_ptr<IoService> io;
    std::shared_ptr<i2pd::client::ClientDestination> dest;
    std::shared_ptr<i2pd::datagram::DatagramDestination> datagram;

    std::string label;
    std::string publicDestination;
    std::string hostAddress;
    Bytes keysBlob;

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

    struct RawTargets {
        std::mutex mutex;
        std::map<std::string, i2pd::data::IdentHash> resolved;
        std::set<std::string> lookups;
    };
    std::shared_ptr<RawTargets> rawTargets = std::make_shared<RawTargets>();
};

EmbeddedEndpoint::~EmbeddedEndpoint()
{
    if (!dest) {
        return;
    }
    const std::shared_ptr<i2pd::client::ClientDestination> closing = dest;
    bazarish::log::info("i2p: closing destination {} ({})",
        label.empty() ? std::string("unnamed") : label, hostAddress);
    std::deque<std::shared_ptr<i2pd::stream::Stream>> pending;
    {
        const std::lock_guard<std::mutex> lock(acceptMutex);
        pending.swap(acceptQueue);
    }
    const std::shared_ptr<i2pd::datagram::DatagramDestination> closingDatagram = datagram;
    dest.reset();
    datagram.reset();
    boost::asio::post(closing->GetService(),
        [closing, closingDatagram = closingDatagram, pending = std::move(pending)]() mutable {
            const std::shared_ptr<i2pd::stream::StreamingDestination> streaming
                = closing->GetStreamingDestination();
            for (const std::shared_ptr<i2pd::stream::Stream>& stream : pending) {
                if (stream) {
                    stream->Close();
                }
            }
            pending.clear();
            closingDatagram.reset();
            closing->Stop();
            boost::asio::post(closing->GetService(), [closing, streaming]() {});
        });
}

bool EmbeddedEndpoint::ready() const { return dest->IsReady(); }

std::string EmbeddedEndpoint::publicBase64() const { return publicDestination; }
std::string EmbeddedEndpoint::routingHost() const { return hostAddress; }
Bytes EmbeddedEndpoint::privateBlob() const { return keysBlob; }

void EmbeddedEndpoint::stop()
{
    stopped->store(true);
    acceptCv.notify_all();
    dgCv.notify_all();
    rawCv.notify_all();
}

void EmbeddedEndpoint::refreshOfflineSignature(const Keys& newTransient)
{
    dest->UpdateOfflineSignature(parseKeys(newTransient.blob()));
    keysBlob = newTransient.blob();
}

std::unique_ptr<backend::StreamBackend> EmbeddedEndpoint::connect(
    const std::string& host, const std::chrono::seconds timeout)
{
    const std::shared_ptr<i2pd::client::ClientDestination> destination = dest;
    std::function<void(i2pd::client::StreamRequestComplete)> issue;
    if (isB32I2pHost(host))
    {
        const std::string label = host.substr(0, host.size() - kB32SuffixLen);
        std::uint8_t raw[64];
        const std::size_t n = i2pd::data::Base32ToByteStream(label, raw, sizeof raw);
        if (n == 32)
        {
            const i2pd::data::IdentHash ident(raw);
            issue = [destination, ident](i2pd::client::StreamRequestComplete cb) {
                destination->CreateStream(cb, ident);
            };
        }
        else
        {
            auto blinded = std::make_shared<i2pd::data::BlindedPublicKey>(std::string_view(label));
            issue = [destination, blinded](i2pd::client::StreamRequestComplete cb) {
                destination->CreateStream(cb, blinded);
            };
        }
    }
    else
    {
        auto identity = std::make_shared<i2pd::data::IdentityEx>();
        if (identity->FromBase64(host) == 0) { return nullptr; }
        const i2pd::data::IdentHash ident = identity->GetIdentHash();
        issue = [destination, ident](i2pd::client::StreamRequestComplete cb) {
                destination->CreateStream(cb, ident);
            };
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline && !*stopped)
    {
        auto promise = std::make_shared<std::promise<std::shared_ptr<i2pd::stream::Stream>>>();
        auto future = promise->get_future();
        issue([promise](std::shared_ptr<i2pd::stream::Stream> s) { promise->set_value(s); });

        const auto remaining = deadline - std::chrono::steady_clock::now();
        const auto attempt = std::min(
            std::chrono::duration_cast<std::chrono::milliseconds>(remaining),
            std::chrono::milliseconds(kDialRoundMillis));
        if (attempt.count() <= 0) { break; }
        std::future_status waited = std::future_status::timeout;
        for (auto spent = std::chrono::milliseconds(0);
             spent < attempt && waited == std::future_status::timeout && !*stopped;
             spent += std::chrono::milliseconds(kDialSliceMillis))
        {
            waited = future.wait_for(std::chrono::milliseconds(kDialSliceMillis));
        }
        if (waited == std::future_status::ready)
        {
            if (auto stream = future.get())
            {
                auto wrapped = std::make_unique<EmbeddedStream>();
                wrapped->stream = std::move(stream);
                wrapped->owner = destination;
                wrapped->stopped = stopped;
                return wrapped;
            }
            if (*stopped) { break; }
            std::this_thread::sleep_for(
                std::chrono::milliseconds(kDialRetryPauseMillis));
        }
    }
    return nullptr;
}

std::unique_ptr<backend::StreamBackend> EmbeddedEndpoint::accept(
    std::string& peerBase64, const std::chrono::seconds timeout)
{
    std::unique_lock<std::mutex> lock(acceptMutex);
    const auto ready = [this] { return !acceptQueue.empty() || *stopped; };
    if (timeout.count() == 0)
    {
        acceptCv.wait(lock, ready);
    }
    else if (!acceptCv.wait_for(lock, timeout, ready))
    {
        return nullptr;
    }
    if (acceptQueue.empty()) { return nullptr; }
    auto stream = acceptQueue.front();
    acceptQueue.pop_front();
    lock.unlock();

    if (stream->GetRemoteIdentity()) { peerBase64 = stream->GetRemoteIdentity()->ToBase64(); }
    auto wrapped = std::make_unique<EmbeddedStream>();
    wrapped->stream = std::move(stream);
    wrapped->owner = dest;
    wrapped->stopped = stopped;
    return wrapped;
}

void EmbeddedEndpoint::sendDatagram(const std::string& host, const void* data, std::size_t size)
{
    if (!datagram) { return; }
    const auto* payload = static_cast<const std::uint8_t*>(data);

    if (isB32I2pHost(host))
    {
        const std::string label = host.substr(0, host.size() - kB32SuffixLen);
        std::uint8_t raw[64];
        const std::size_t n = i2pd::data::Base32ToByteStream(label, raw, sizeof raw);
        if (n == 32)
        {
            datagram->SendDatagramTo(payload, size, i2pd::data::IdentHash(raw));
        }
        else
        {
            auto blinded = std::make_shared<i2pd::data::BlindedPublicKey>(std::string_view(label));
            const std::shared_ptr<i2pd::datagram::DatagramDestination> sender = datagram;
            std::vector<std::uint8_t> copy(payload, payload + size);
            dest->RequestDestinationWithEncryptedLeaseSet(blinded,
                [sender, copy](std::shared_ptr<i2pd::data::LeaseSet> ls)
                {
                    if (ls) { sender->SendDatagramTo(copy.data(), copy.size(), ls->GetIdentHash()); }
                });
        }
    }
    else
    {
        auto identity = std::make_shared<i2pd::data::IdentityEx>();
        if (identity->FromBase64(host) > 0)
        {
            datagram->SendDatagramTo(payload, size, identity->GetIdentHash());
        }
    }
}

std::vector<std::uint8_t> EmbeddedEndpoint::receiveDatagram(std::string& peerBase64,
    std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(dgMutex);
    if (!dgCv.wait_for(lock, timeout, [this] { return !dgQueue.empty() || *stopped; })
        || dgQueue.empty())
    {
        return {};
    }
    auto incoming = std::move(dgQueue.front());
    dgQueue.pop_front();
    lock.unlock();
    peerBase64 = std::move(incoming.from);
    return std::move(incoming.payload);
}

void EmbeddedEndpoint::sendRawDatagram(const std::string& host, const void* data, std::size_t size)
{
    if (!datagram) { return; }
    const auto* payload = static_cast<const std::uint8_t*>(data);

    if (isB32I2pHost(host))
    {
        const std::string label = host.substr(0, host.size() - kB32SuffixLen);
        std::uint8_t rawHash[64];
        const std::size_t n = i2pd::data::Base32ToByteStream(label, rawHash, sizeof rawHash);
        if (n == 32)
        {
            datagram->SendRawDatagramTo(payload, size, i2pd::data::IdentHash(rawHash));
        }
        else
        {
            const std::shared_ptr<RawTargets> targets = rawTargets;
            {
                const std::lock_guard<std::mutex> lock(targets->mutex);
                const auto known = targets->resolved.find(host);
                if (known != targets->resolved.end())
                {
                    datagram->SendRawDatagramTo(payload, size, known->second);
                    return;
                }
                if (!targets->lookups.insert(host).second)
                {
                    return;
                }
            }
            bazarish::log::info("i2p: looking up {} to send it datagrams", host);
            auto blinded = std::make_shared<i2pd::data::BlindedPublicKey>(std::string_view(label));
            dest->RequestDestinationWithEncryptedLeaseSet(blinded,
                [targets, host](std::shared_ptr<i2pd::data::LeaseSet> ls)
                {
                    const std::lock_guard<std::mutex> lock(targets->mutex);
                    targets->lookups.erase(host);
                    if (!ls)
                    {
                        bazarish::log::warn("i2p: {} has no leaseset; datagrams to it go nowhere",
                            host);
                        return;
                    }
                    targets->resolved[host] = ls->GetIdentHash();
                    bazarish::log::info("i2p: {} answered; datagrams to it can go", host);
                });
        }
    }
    else
    {
        auto identity = std::make_shared<i2pd::data::IdentityEx>();
        if (identity->FromBase64(host) > 0)
        {
            datagram->SendRawDatagramTo(payload, size, identity->GetIdentHash());
        }
    }
}

std::vector<std::uint8_t> EmbeddedEndpoint::receiveRawDatagram(std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(rawMutex);
    if (!rawCv.wait_for(lock, timeout, [this] { return !rawQueue.empty() || *stopped; })
        || rawQueue.empty())
    {
        return {};
    }
    auto payload = std::move(rawQueue.front());
    rawQueue.pop_front();
    return payload;
}

class EmbeddedRouter final : public backend::RouterBackend {
public:
    explicit EmbeddedRouter(const RouterConfig& config);

    Capabilities capabilities() const override;
    void start() override;
    void stop() override;
    bool running() const override;
    bool ready() const override;
    int knownRouters() const override;
    int floodfills() const override;
    int transitTunnels() const override;
    int inboundTunnels() const override;
    int outboundTunnels() const override;
    std::vector<TransportPeer> transportPeers() const override;
    std::vector<LocalDestination> localDestinations() const override;
    void setSocksProxy(const std::string& host, int port) override;
    ProxyState proxyState() const override;
    void setReseedUrls(const std::vector<std::string>& urls) override;
    ReseedState reseedState() const override;
    std::shared_ptr<backend::EndpointBackend> createEndpoint(const EndpointConfig& config) override;
    void retagEndpoint(
        const backend::EndpointBackend& endpoint, std::string label, std::string owner) override;

    bool owns = false;
    bool inited = false;
    bool started = false;
    std::string builtInReseedUrls;
    std::shared_ptr<IoService> io;

    struct DestEntry {
        std::weak_ptr<i2pd::client::ClientDestination> dest;
        std::string label;
        std::string owner;
        std::string host;
        bool published = false;
    };
    mutable std::mutex destsMutex;
    mutable std::vector<DestEntry> dests;

    ~EmbeddedRouter()
    {
        io.reset();
        if (started)
        {
            i2pd::api::StopI2P();
        }
        if (inited)
        {
            i2pd::api::TerminateI2P();
        }
        if (owns) { g_routerLive = false; }
    }
};

namespace {

struct ReseedChoice
{
    std::string urls;
    std::string file;
};

// i2pd reads reseed.file before reseed.urls and takes one archive, so a second
// local archive would be dropped without a word.
ReseedChoice reseedChoiceFor(const std::vector<std::string>& reseedUrls)
{
    ReseedChoice choice;
    for (const std::string& url : reseedUrls)
    {
        if (url.rfind("https://", 0) != 0)
        {
            if (!choice.file.empty())
            {
                throw std::invalid_argument("i2p: one local reseed archive at a time");
            }
            choice.file = url;
            continue;
        }
        choice.urls += (choice.urls.empty() ? "" : ",") + url;
        if (choice.urls.back() != '/')
        {
            choice.urls += '/';
        }
    }
    return choice;
}

}  // namespace

EmbeddedRouter::EmbeddedRouter(const RouterConfig& config)
{
    (void)reseedChoiceFor(config.reseedUrls);

    bool expected = false;
    if (!g_routerLive.compare_exchange_strong(expected, true))
    {
        throw std::runtime_error("bazarish::i2p::Router: only one router per process");
    }
    owns = true;

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
    args.push_back("--persist.profiles=false");

    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) { argv.push_back(arg.data()); }

    i2pd::api::InitI2P(static_cast<int>(argv.size()), argv.data(), "bazarish-i2p");
    inited = true;
    bazarish::log::info("i2p: engine initialised");
    i2pd::config::GetOption("reseed.urls", builtInReseedUrls);
    setReseedUrls(config.reseedUrls);
    setSocksProxy(config.socksProxyHost, config.socksProxyPort);
    start();
}

void EmbeddedRouter::start()
{
    if (started) { return; }
    i2pd::log::Logger().SendTo([](LogLevel level, const std::string& text)
    {
        if (!i2pLogging()) { return; }
        bazarish::log::emit(mapLevel(level), text);
    });
    i2pd::log::Logger().SetLogLevel(i2pLogging() ? "warn" : "none");
    i2pd::api::StartI2P();
    started = true;
    bazarish::log::info("i2p: engine running");
    io = std::make_shared<IoService>(ioContextCount());
}

void EmbeddedRouter::setReseedUrls(const std::vector<std::string>& urls)
{
    const ReseedChoice choice = reseedChoiceFor(urls);
    const std::string wanted = choice.urls.empty() ? builtInReseedUrls : choice.urls;
    if (!i2pd::config::SetOption("reseed.file", choice.file)
        || !i2pd::config::SetOption("reseed.urls", wanted))
    {
        throw std::runtime_error("bazarish::i2p: this engine has no reseed option to set");
    }
}

ReseedState EmbeddedRouter::reseedState() const
{
    ReseedState state;
    i2pd::config::GetOption("reseed.urls", state.urls);
    i2pd::config::GetOption("reseed.file", state.file);
    return state;
}

void EmbeddedRouter::setSocksProxy(const std::string& host, const int port)
{
    const bool wanted = !host.empty() && port > 0;
    const std::string url
        = wanted ? "socks://" + host + ":" + std::to_string(port) : std::string();
    i2pd::config::SetOption("ntcp2.proxy", url);
    i2pd::config::SetOption("reseed.proxy", url);
    i2pd::config::SetOption("ssu2.proxy", std::string());
    i2pd::config::SetOption("ssu2.enabled", !wanted);
    if (wanted)
    {
        bazarish::log::info("i2p: clearnet side through {}, SSU2 off", url);
    }
}

ProxyState EmbeddedRouter::proxyState() const
{
    ProxyState state;
    i2pd::config::GetOption("ntcp2.proxy", state.ntcp2);
    i2pd::config::GetOption("ssu2.proxy", state.ssu2);
    i2pd::config::GetOption("reseed.proxy", state.reseed);
    i2pd::config::GetOption("ssu2.enabled", state.ssu2Enabled);
    return state;
}

void EmbeddedRouter::stop()
{
    if (!started) { return; }
    io.reset();
    i2pd::api::StopI2P();
    started = false;
}

bool EmbeddedRouter::running() const { return started; }

bool EmbeddedRouter::ready() const
{
    if (i2pd::data::netdb.GetNumRouters() == 0) { return false; }
    auto pool = i2pd::tunnel::tunnels.GetExploratoryPool();
    return pool && pool->HasOutboundTunnels();
}

int EmbeddedRouter::knownRouters() const { return i2pd::data::netdb.GetNumRouters(); }
int EmbeddedRouter::floodfills() const { return i2pd::data::netdb.GetNumFloodfills(); }
int EmbeddedRouter::transitTunnels() const
{
    return static_cast<int>(i2pd::tunnel::tunnels.CountTransitTunnels());
}
int EmbeddedRouter::inboundTunnels() const
{
    return static_cast<int>(i2pd::tunnel::tunnels.CountInboundTunnels());
}
int EmbeddedRouter::outboundTunnels() const
{
    return static_cast<int>(i2pd::tunnel::tunnels.CountOutboundTunnels());
}

std::vector<TransportPeer> EmbeddedRouter::transportPeers() const
{
    std::vector<TransportPeer> peers;
    const auto collect = [&peers](const auto& sessions, const char* name) {
        for (const auto& entry : sessions) {
            const auto& session = entry.second;
            if (!session || !session->IsEstablished()) { continue; }
            const auto remote = session->GetRemoteIdentity();
            if (!remote) { continue; }
            TransportPeer peer;
            peer.ident = remote->GetIdentHash().ToBase64().substr(0, 8);
            peer.transport = name;
            peer.outbound = session->IsOutgoing();
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
    if (auto* const ssu2 = i2pd::transport::transports.GetSSU2Server()) {
        i2pd::transport::SSU2Server::SSU2Sessions sessions;
        if (ssu2->GetSSU2Sessions(sessions).wait_for(std::chrono::seconds(kSessionSnapshotSeconds))
            == std::future_status::ready) {
            collect(sessions, "SSU2");
        }
    }
    return peers;
}

void EmbeddedRouter::retagEndpoint(
    const backend::EndpointBackend& endpoint, std::string label, std::string owner)
{
    const std::shared_ptr<i2pd::client::ClientDestination> dest
        = static_cast<const EmbeddedEndpoint&>(endpoint).dest;
    std::lock_guard<std::mutex> lock(destsMutex);
    for (DestEntry& entry : dests) {
        if (entry.dest.lock() == dest) {
            entry.label = std::move(label);
            entry.owner = std::move(owner);
            return;
        }
    }
}

std::vector<LocalDestination> EmbeddedRouter::localDestinations() const
{
    constexpr int kTunnelCountProbe = 64;
    std::vector<LocalDestination> live;
    std::lock_guard<std::mutex> lock(destsMutex);
    std::erase_if(dests, [](const DestEntry& entry) { return entry.dest.expired(); });
    for (const DestEntry& entry : dests) {
        const std::shared_ptr<i2pd::client::ClientDestination> dest = entry.dest.lock();
        if (!dest) { continue; }
        LocalDestination info;
        info.label = entry.label;
        info.owner = entry.owner;
        info.host = entry.host;
        info.published = entry.published;
        info.ready = dest->IsReady();
        info.remoteLeaseSets = dest->GetNumRemoteLeaseSets();
        const auto tunnelPool = dest->GetTunnelPool();
        info.closing = !tunnelPool || !tunnelPool->IsActive();
        if (const auto pool = tunnelPool) {
            info.inboundTunnels = static_cast<int>(pool->GetInboundTunnels(kTunnelCountProbe).size());
            const auto outbound = pool->GetOutboundTunnelsList();
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

std::shared_ptr<backend::EndpointBackend> EmbeddedRouter::createEndpoint(
    const EndpointConfig& config)
{
    const Keys keys = config.keys.has_value() ? config.keys.value() : Keys::generate();

    auto impl = std::make_shared<EmbeddedEndpoint>();
    impl->label = config.label;
    impl->publicDestination = keys.publicBase64();
    impl->hostAddress = bazarish::i2p::routingHost(impl->publicDestination);
    impl->keysBlob = keys.blob();

    i2pd::util::Mapping params;
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_TYPE,
        std::to_string(i2pd::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2));
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_ENCRYPTION_TYPE, "4");
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

    impl->io = io;
    impl->dest = std::make_shared<i2pd::client::ClientDestination>(
        config.realtime ? impl->io->reserved() : impl->io->next(),
        parseKeys(keys.blob()), config.published, &params);
    impl->dest->Start();
    {
        std::lock_guard<std::mutex> lock(destsMutex);
        std::erase_if(dests,
            [](const DestEntry& entry) { return entry.dest.expired(); });
        dests.push_back(DestEntry{
            impl->dest, config.label, config.owner, impl->hostAddress, config.published});
    }

    const std::weak_ptr<EmbeddedEndpoint> weak = impl;
    impl->dest->AcceptStreams([weak](std::shared_ptr<i2pd::stream::Stream> stream)
    {
        const std::shared_ptr<EmbeddedEndpoint> held = weak.lock();
        if (!held || !stream) { return; }
        {
            std::lock_guard<std::mutex> lock(held->acceptMutex);
            held->acceptQueue.push_back(std::move(stream));
        }
        held->acceptCv.notify_one();
    });

    impl->datagram = impl->dest->CreateDatagramDestination();
    impl->datagram->SetReceiver([weak](const i2pd::data::IdentityEx& from, std::uint16_t,
        std::uint16_t, const std::uint8_t* buf, std::size_t len, const i2pd::util::Mapping*)
    {
        const std::shared_ptr<EmbeddedEndpoint> held = weak.lock();
        if (!held) { return; }
        EmbeddedEndpoint::Incoming incoming;
        incoming.from = from.ToBase64();
        incoming.payload.assign(buf, buf + len);
        {
            std::lock_guard<std::mutex> lock(held->dgMutex);
            held->dgQueue.push_back(std::move(incoming));
        }
        held->dgCv.notify_one();
    });
    impl->datagram->SetRawReceiver([weak](std::uint16_t, std::uint16_t,
        const std::uint8_t* buf, std::size_t len)
    {
        const std::shared_ptr<EmbeddedEndpoint> held = weak.lock();
        if (!held) { return; }
        {
            std::lock_guard<std::mutex> lock(held->rawMutex);
            held->rawQueue.emplace_back(buf, buf + len);
        }
        held->rawCv.notify_one();
    });

    return impl;
}

Capabilities EmbeddedRouter::capabilities() const
{
    Capabilities what;
    what.routerCounters = true;
    what.destinationCounters = true;
    what.netDbSample = true;
    what.proxy = true;
    what.offlineKeys = true;
    what.reseed = true;
    return what;
}

namespace backend {

std::unique_ptr<RouterBackend> makeEmbeddedRouter(const RouterConfig& config)
{
    return std::make_unique<EmbeddedRouter>(config);
}

Bytes generateKeysBlob()
{
    ensureCryptoInit();
    return serializeKeys(i2pd::data::PrivateKeys::CreateRandomKeys(kSigType));
}

Bytes issueTransientBlob(const Bytes& master, const int days)
{
    const i2pd::data::PrivateKeys keys = parseKeys(master);
    const std::uint64_t midnight = currentMidnight();
    const std::uint64_t expires = midnight + days*i2pd::data::SECONDS_PER_DAY;
    Bytes blob
        = serializeKeys(keys.CreateOfflineKeys(kSigType, static_cast<std::uint32_t>(expires)));
    const Bytes batch = createB33OfflineKeys(keys, days, midnight);
    blob.insert(blob.end(), batch.begin(), batch.end());
    return blob;
}

int b33OfflineKeyDays(const Bytes& blob)
{
    const i2pd::data::PrivateKeys keys = parseKeys(blob);
    const i2pd::data::B33OfflineKeys& batch = keys.GetB33OfflineKeys();
    if (batch.GetLen() < i2pd::data::B33_OFFLINE_KEYS_HEADER_LENGTH) { return 0; }
    char today[9];
    i2pd::util::GetDateString(currentMidnight(), today);
    if (!i2pd::data::OfflinePrivateKeys(keys, today).IsOfflineSignature()) { return 0; }
    return bufbe16toh(batch.GetBuffer() + i2pd::data::B33_OFFLINE_KEYS_HEADER_LENGTH - 2);
}

}  // namespace backend

}  // namespace bazarish::i2p
