// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "I2pBackend.hpp"

#include "bazarish/I2pAddress.hpp"
#include "bazarish/Log.hpp"
#include "bazarish/RawPathChooser.hpp"

#include "OpenSslHandles.hpp"

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
#include "RouterContext.h"
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
#include <array>
#include <cstring>
#include <memory>
#include <ostream>
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
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace i2pd = ::i2p;

namespace bazarish::i2p {

using backend::DestTag;

namespace {

constexpr i2pd::data::SigningKeyType kSigType = i2pd::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519;
constexpr i2pd::data::CryptoKeyType kSeededCryptoType
    = i2pd::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD;
// RFC 8032 and RFC 7748: Ed25519 and X25519 raw keys are both 32 bytes.
constexpr std::size_t kRawKeyBytes = 32;
constexpr std::size_t kSigningFieldOffset = sizeof(i2pd::data::Identity::publicKey);
constexpr std::size_t kSigningFieldBytes = sizeof(i2pd::data::Identity::signingKey);
constexpr i2pd::data::SigningKeyType kB33SigType
    = i2pd::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519;
constexpr int kMaxB33Days = 0xFFFF;
// i2pd's GetDateString writes "YYYYMMDD" and its terminator.
constexpr std::size_t kDateStringBytes = 9;
constexpr std::size_t kB32SuffixLen = 8;
constexpr std::size_t kB32LabelBytesMax = 64;
constexpr std::size_t kIdentHashBytes = 32;
constexpr std::int64_t kMillisPerSecond = 1000;
constexpr int kReceivePollSeconds = 5;
constexpr int kServerShareRatio = 100;
constexpr int kSessionSnapshotSeconds = 2;
constexpr int kDialRoundMillis = 30000;
constexpr int kDialSliceMillis = 250;
constexpr int kDialRetryPauseMillis = 2000;
constexpr std::chrono::seconds kRawLookupPause{2};
// RFC 862's echo port: path probes and their echoes, apart from the call media on port 0.
constexpr std::uint16_t kPathProbePort = 7;
constexpr std::uint8_t kPathProbe = 1;
constexpr std::uint8_t kPathEcho = 2;
constexpr std::size_t kPathProbeIdOffset = 1;
constexpr std::size_t kPathProbeBytes = kPathProbeIdOffset + sizeof(std::uint64_t);
constexpr std::chrono::seconds kPathPeerActive{5};

// libi2pd's crypto state must be initialised once before any key operation.
void ensureCryptoInit()
{
    static const bool kInit = []() { i2pd::crypto::InitCrypto(false); return true; }();
    (void)kInit;
}

LogLevel i2pdLevelOf(const I2pLogLevel level)
{
    switch (level)
    {
        case I2pLogLevel::eNone:  return eLogNone;
        case I2pLogLevel::eError: return eLogError;
        case I2pLogLevel::eWarn:  return eLogWarning;
        case I2pLogLevel::eInfo:  return eLogInfo;
        case I2pLogLevel::eDebug: return eLogDebug;
    }
    return eLogNone;
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

Bytes rawPublicOf(const int type, const Bytes& rawPrivate)
{
    const std::unique_ptr<EVP_PKEY, ossl::Freer<&EVP_PKEY_free>> key(
        EVP_PKEY_new_raw_private_key(type, nullptr, rawPrivate.data(), rawPrivate.size()));
    if (!key)
    {
        throw std::runtime_error("bazarish::i2p: a seed is not a raw private key");
    }
    Bytes raw(kRawKeyBytes);
    std::size_t length = raw.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), raw.data(), &length) != 1 || length != raw.size())
    {
        throw std::runtime_error("bazarish::i2p: no raw public key for a seed");
    }
    return raw;
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
            Lane& l = *lane;
            l.worker = std::thread([&l]
            {
                while (l.running)
                {
                    try
                    {
                        l.ctx.run();
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
    return I2PD_VERSION;
}

void backend::setEmbeddedLogLevel(const I2pLogLevel level)
{
    i2pd::log::Logger().SetLogLevel(std::string(i2pLogLevelName(level)));
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

class EmbeddedStream final : public backend::StreamBackend {
public:
    ~EmbeddedStream() override { close(); }

    void setReadTimeout(const std::chrono::seconds timeout) override
    {
        readTimeoutSeconds = static_cast<int>(timeout.count());
    }
    std::size_t readSome(ByteBuffer buffer) override;
    void writeAll(ByteView data) override;
    std::size_t pendingBytes() const override;
    void close() override;
    void tellRenewedLeaseSet();

    std::shared_ptr<i2pd::stream::Stream> stream;
    std::shared_ptr<i2pd::client::ClientDestination> owner;
    std::shared_ptr<std::atomic<bool>> stopped;
    std::atomic<bool> closed{false};
    std::atomic<int> readTimeoutSeconds{0};
    struct Told {
        std::mutex mutex;
        std::shared_ptr<const i2pd::data::LocalLeaseSet> leaseSet;
    };
    const std::shared_ptr<Told> told = std::make_shared<Told>();
};

// i2pd sends a renewed lease set only with a message: a silent stream's far end loses the way back.
void EmbeddedStream::tellRenewedLeaseSet()
{
    boost::asio::post(owner->GetService(), [owner = owner, stream = stream, told = told]() {
        const std::shared_ptr<const i2pd::data::LocalLeaseSet> current = owner->GetLeaseSet();
        bool first = false;
        {
            const std::lock_guard<std::mutex> lock(told->mutex);
            if (current == nullptr || current == told->leaseSet) {
                return;
            }
            first = told->leaseSet == nullptr;
            told->leaseSet = current;
        }
        const std::shared_ptr<const i2pd::data::LeaseSet> remote = stream->GetRemoteLeaseSet();
        const std::shared_ptr<i2pd::stream::StreamingDestination> streaming
            = owner->GetStreamingDestination();
        if (first || remote == nullptr || streaming == nullptr) {
            return;
        }
        streaming->SendPing(remote);
    });
}

std::size_t EmbeddedStream::readSome(const ByteBuffer buffer)
{
    if (!stream || closed || (stopped && *stopped) || buffer.empty()) { return 0; }
    const std::chrono::seconds timeout{readTimeoutSeconds.load()};
    const auto started = std::chrono::steady_clock::now();
    while (!closed && !(stopped && *stopped))
    {
        auto promise = std::make_shared<std::promise<std::size_t>>();
        auto future = promise->get_future();
        stream->AsyncReceive(boost::asio::buffer(buffer.data(), buffer.size()),
            [promise](const boost::system::error_code&, std::size_t received)
            {
                promise->set_value(received);
            }, kReceivePollSeconds);
        const std::size_t received = future.get();
        if (received > 0) { return received; }
        if (isClosedStatus(stream->GetStatus())) { return 0; }
        tellRenewedLeaseSet();
        if (timeout.count() > 0 && std::chrono::steady_clock::now() - started >= timeout)
        {
            throw std::runtime_error("bazarish::i2p: nothing read within "
                + std::to_string(timeout.count()) + "s");
        }
    }
    return 0;
}

void EmbeddedStream::writeAll(const ByteView data)
{
    if (!stream) { throw std::runtime_error("bazarish::i2p: write on a closed stream"); }
    std::size_t off = 0;
    while (off < data.size())
    {
        const ByteView rest = data.subspan(off);
        const std::size_t written = stream->Send(rest.data(), rest.size());
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

namespace {

struct LivePath {
    std::shared_ptr<i2pd::tunnel::OutboundTunnel> tunnel;
    std::shared_ptr<const i2pd::data::Lease> lease;
};

struct RawRoute {
    i2pd::data::IdentHash ident;
    RawPathChooser chooser;
    std::map<RawPath, LivePath> live;
    std::chrono::steady_clock::time_point lastSent{};
};

bool leaseLasts(const i2pd::data::Lease& lease)
{
    return !lease.ExpiresWithin(i2pd::datagram::DATAGRAM_SESSION_LEASE_HANDOVER_WINDOW);
}

std::shared_ptr<i2pd::garlic::GarlicRoutingPath> routingPathOf(
    const RawRoute& route, const std::optional<RawPath>& path)
{
    if (!path.has_value())
    {
        return nullptr;
    }
    const auto found = route.live.find(path.value());
    if (found == route.live.end() || !found->second.tunnel->IsEstablished()
        || !leaseLasts(*found->second.lease))
    {
        return nullptr;
    }
    return std::make_shared<i2pd::garlic::GarlicRoutingPath>(
        i2pd::garlic::GarlicRoutingPath{found->second.tunnel, found->second.lease, 0, 0});
}

std::vector<RawPath> livePaths(RawRoute& route, i2pd::client::ClientDestination& dest,
    const i2pd::datagram::DatagramSession& session)
{
    route.live.clear();
    const std::shared_ptr<const i2pd::data::LeaseSet> leaseSet = session.GetRemoteLeaseSet();
    if (!leaseSet)
    {
        return {};
    }
    const auto leases = leaseSet->GetNonExpiredLeases();
    std::vector<RawPath> paths;
    for (const auto& tunnel : dest.GetTunnelPool()->GetOutboundTunnelsList())
    {
        if (!tunnel->IsEstablished())
        {
            continue;
        }
        for (const auto& lease : leases)
        {
            if (!leaseLasts(*lease))
            {
                continue;
            }
            RawPath path;
            path.outboundTunnel = tunnel->GetTunnelID();
            std::copy_n(lease->tunnelGateway.data(), path.leaseGateway.size(),
                path.leaseGateway.begin());
            path.leaseTunnel = lease->tunnelID;
            route.live.emplace(path, LivePath{tunnel, lease});
            paths.push_back(path);
        }
    }
    return paths;
}

void sendOnRoute(i2pd::datagram::DatagramDestination& datagram,
    const std::shared_ptr<i2pd::datagram::DatagramSession>& session, const RawRoute& route,
    const std::vector<std::uint8_t>& payload, const std::uint16_t port)
{
    if (const auto path = routingPathOf(route, route.chooser.chosen()))
    {
        session->SetRoutingPath(path);
    }
    datagram.SendRawDatagram(session, payload.data(), payload.size(), 0, port);
    datagram.FlushSendQueue(session);
}

// The path the session had goes back afterwards, so a probe never moves the call.
void sendProbe(i2pd::datagram::DatagramDestination& datagram,
    const std::shared_ptr<i2pd::datagram::DatagramSession>& session, const RawRoute& route,
    const std::shared_ptr<i2pd::garlic::GarlicRoutingPath>& kept,
    const RawPathChooser::Probe& probe)
{
    const auto path = routingPathOf(route, probe.path);
    if (!path)
    {
        return;
    }
    std::vector<std::uint8_t> frame(kPathProbeBytes);
    frame[0] = kPathProbe;
    htobe64buf(frame.data() + kPathProbeIdOffset, probe.id);
    session->SetRoutingPath(path);
    datagram.SendRawDatagram(session, frame.data(), frame.size(), 0, kPathProbePort);
    datagram.FlushSendQueue(session);
    session->SetRoutingPath(kept);
}

void reportPath(const std::string& host, const RawPathChooser& chooser,
    const std::optional<RawPath>& before)
{
    const std::optional<RawPath> chosen = chooser.chosen();
    if (!chosen.has_value() || chosen == before)
    {
        return;
    }
    const std::chrono::milliseconds roundTrip = chooser.roundTrip(chosen.value()).value();
    const auto was = before.has_value() ? chooser.roundTrip(before.value()) : std::nullopt;
    if (was.has_value())
    {
        bazarish::log::info("i2p: datagrams to {} moved to a {} ms path from a {} ms one",
            host, roundTrip.count(), was->count());
        return;
    }
    bazarish::log::info("i2p: datagrams to {} take a {} ms path", host, roundTrip.count());
}

}  // namespace

class EmbeddedEndpoint final : public backend::EndpointBackend,
                               public std::enable_shared_from_this<EmbeddedEndpoint> {
public:
    ~EmbeddedEndpoint() override;

    bool ready() const override;
    bool lost() const override { return stopped->load(); }
    std::string publicBase64() const override;
    std::string routingHost() const override;
    void refreshOfflineSignature(const Keys& newTransient) override;
    void setLeaseSetReaderKey(const Bytes& rawPrivate) override;
    std::unique_ptr<backend::StreamBackend> connect(
        const std::string& host, std::chrono::seconds timeout) override;
    std::unique_ptr<backend::StreamBackend> accept(
        std::string& peerBase64, std::chrono::seconds timeout) override;
    void sendDatagram(const std::string& host, ByteView data) override;
    Datagram receiveDatagram(std::chrono::milliseconds timeout) override;
    void sendRawDatagram(const std::string& host, ByteView data) override;
    std::vector<std::uint8_t> receiveRawDatagram(std::chrono::milliseconds timeout) override;
    void stop() override;

    std::shared_ptr<std::atomic<bool>> stopped = std::make_shared<std::atomic<bool>>(false);

    std::shared_ptr<IoService> io;
    std::shared_ptr<i2pd::client::ClientDestination> dest;
    std::shared_ptr<i2pd::datagram::DatagramDestination> datagram;

    std::shared_ptr<DestTag> tag;
    std::string publicDestination;
    std::string hostAddress;

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
        std::map<std::string, i2pd::data::IdentHash> resolved;
        std::set<std::string> lookups;
        std::map<std::string, std::vector<std::uint8_t>> waiting;
        std::map<std::string, std::chrono::steady_clock::time_point> missedAt;
        bool steered = false;
        std::map<std::string, RawRoute> routes;
    };
    std::shared_ptr<RawTargets> rawTargets = std::make_shared<RawTargets>();

    void answerPathProbe(ByteView frame);

private:
    static void sendRawOnLane(const std::shared_ptr<i2pd::client::ClientDestination>& dest,
        const std::shared_ptr<i2pd::datagram::DatagramDestination>& datagram,
        const std::shared_ptr<RawTargets>& targets, const std::string& host,
        const std::vector<std::uint8_t>& payload);
    static void deliverRaw(i2pd::client::ClientDestination& dest,
        i2pd::datagram::DatagramDestination& datagram, RawTargets& targets,
        const std::string& host, const i2pd::data::IdentHash& ident,
        const std::vector<std::uint8_t>& payload);
};

EmbeddedEndpoint::~EmbeddedEndpoint()
{
    if (!dest) {
        return;
    }
    const std::shared_ptr<i2pd::client::ClientDestination> closing = dest;
    const std::string label = tag->label();
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

void EmbeddedEndpoint::stop()
{
    {
        const std::scoped_lock lock(acceptMutex, dgMutex, rawMutex);
        stopped->store(true);
    }
    acceptCv.notify_all();
    dgCv.notify_all();
    rawCv.notify_all();
}

void EmbeddedEndpoint::setLeaseSetReaderKey(const Bytes& rawPrivate)
{
    if (rawPrivate.size() != backend::kLeaseSetKeyBytes) {
        throw std::invalid_argument("a lease-set reader key is 32 raw bytes");
    }
    dest->SetLeaseSetPrivKey(rawPrivate.data());
}

void EmbeddedEndpoint::refreshOfflineSignature(const Keys& newTransient)
{
    dest->UpdateOfflineSignature(parseKeys(newTransient.blob()));
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
    if (!acceptCv.wait_for(lock, timeout, ready))
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

void EmbeddedEndpoint::sendDatagram(const std::string& host, const ByteView data)
{
    if (!datagram) { return; }
    const std::shared_ptr<i2pd::datagram::DatagramDestination> sender = datagram;
    std::vector<std::uint8_t> copy(data.begin(), data.end());
    const auto sendTo = [this, &sender, &copy](const i2pd::data::IdentHash& to)
    {
        boost::asio::post(dest->GetService(), [sender, copy = std::move(copy), to]()
        {
            sender->SendDatagramTo(copy.data(), copy.size(), to);
        });
    };

    if (isB32I2pHost(host))
    {
        const std::string label = host.substr(0, host.size() - kB32SuffixLen);
        std::uint8_t raw[64];
        const std::size_t n = i2pd::data::Base32ToByteStream(label, raw, sizeof raw);
        if (n == 32)
        {
            sendTo(i2pd::data::IdentHash(raw));
        }
        else
        {
            auto blinded = std::make_shared<i2pd::data::BlindedPublicKey>(std::string_view(label));
            dest->RequestDestinationWithEncryptedLeaseSet(blinded,
                [sender, copy = std::move(copy)](std::shared_ptr<i2pd::data::LeaseSet> ls)
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
            sendTo(identity->GetIdentHash());
        }
    }
}

Datagram EmbeddedEndpoint::receiveDatagram(const std::chrono::milliseconds timeout)
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
    return {std::move(incoming.from), std::move(incoming.payload)};
}

void EmbeddedEndpoint::sendRawDatagram(const std::string& host, const ByteView data)
{
    if (!datagram) { return; }
    // libi2pd keeps a destination's garlic state for the one thread that runs it.
    boost::asio::post(dest->GetService(),
        [destination = dest, sender = datagram, targets = rawTargets, host,
            copy = std::vector<std::uint8_t>(data.begin(), data.end())]()
        {
            sendRawOnLane(destination, sender, targets, host, copy);
        });
}

void EmbeddedEndpoint::sendRawOnLane(const std::shared_ptr<i2pd::client::ClientDestination>& dest,
    const std::shared_ptr<i2pd::datagram::DatagramDestination>& datagram,
    const std::shared_ptr<RawTargets>& targets, const std::string& host,
    const std::vector<std::uint8_t>& payload)
{
    if (!isB32I2pHost(host))
    {
        auto identity = std::make_shared<i2pd::data::IdentityEx>();
        if (identity->FromBase64(host) > 0)
        {
            deliverRaw(*dest, *datagram, *targets, host, identity->GetIdentHash(), payload);
        }
        return;
    }
    const std::string label = host.substr(0, host.size() - kB32SuffixLen);
    std::uint8_t rawHash[64];
    if (i2pd::data::Base32ToByteStream(label, rawHash, sizeof rawHash) == 32)
    {
        deliverRaw(*dest, *datagram, *targets, host, i2pd::data::IdentHash(rawHash), payload);
        return;
    }
    const auto known = targets->resolved.find(host);
    if (known != targets->resolved.end())
    {
        // libi2pd renews a remote lease set by identity, which an encrypted one is never stored under.
        if (dest->FindLeaseSet(known->second))
        {
            deliverRaw(*dest, *datagram, *targets, host, known->second, payload);
            return;
        }
        targets->resolved.erase(known);
    }
    if (targets->lookups.count(host) != 0)
    {
        targets->waiting[host] = payload;
        return;
    }
    // libi2pd answers a lookup from a destination without tunnels at once, with nothing.
    if (!dest->IsReady())
    {
        return;
    }
    const auto missed = targets->missedAt.find(host);
    const bool first = missed == targets->missedAt.end();
    if (!first && std::chrono::steady_clock::now() - missed->second < kRawLookupPause)
    {
        return;
    }
    targets->lookups.insert(host);
    targets->waiting[host] = payload;
    if (first)
    {
        bazarish::log::info("i2p: looking up {} to send it datagrams", host);
    }
    auto blinded = std::make_shared<i2pd::data::BlindedPublicKey>(std::string_view(label));
    dest->RequestDestinationWithEncryptedLeaseSet(blinded,
        [weakDest = std::weak_ptr(dest), weakDatagram = std::weak_ptr(datagram), targets, host,
            first](std::shared_ptr<i2pd::data::LeaseSet> ls)
        {
            targets->lookups.erase(host);
            const auto held = targets->waiting.find(host);
            const std::vector<std::uint8_t> waiting = std::move(held->second);
            targets->waiting.erase(held);
            if (!ls)
            {
                targets->missedAt[host] = std::chrono::steady_clock::now();
                if (first)
                {
                    bazarish::log::warn("i2p: {} has no leaseset yet; it is asked again"
                        " every {} s", host, kRawLookupPause.count());
                }
                return;
            }
            targets->resolved[host] = ls->GetIdentHash();
            targets->missedAt.erase(host);
            bazarish::log::info("i2p: {} answered; datagrams to it can go", host);
            const std::shared_ptr<i2pd::client::ClientDestination> destination = weakDest.lock();
            const std::shared_ptr<i2pd::datagram::DatagramDestination> sender = weakDatagram.lock();
            if (destination && sender)
            {
                deliverRaw(*destination, *sender, *targets, host, ls->GetIdentHash(), waiting);
            }
        });
}

void EmbeddedEndpoint::deliverRaw(i2pd::client::ClientDestination& dest,
    i2pd::datagram::DatagramDestination& datagram, RawTargets& targets, const std::string& host,
    const i2pd::data::IdentHash& ident, const std::vector<std::uint8_t>& payload)
{
    if (!targets.steered)
    {
        datagram.SendRawDatagramTo(payload.data(), payload.size(), ident);
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    RawRoute& route = targets.routes[host];
    route.ident = ident;
    route.lastSent = now;
    const std::shared_ptr<i2pd::datagram::DatagramSession> session = datagram.GetSession(ident);
    sendOnRoute(datagram, session, route, payload, 0);
    // No path yet means no garlic session yet: a probe could not be pinned to its path.
    const std::shared_ptr<i2pd::garlic::GarlicRoutingPath> kept = session->GetRoutingPath();
    if (!kept || !route.chooser.probeDue(now))
    {
        return;
    }
    const std::optional<RawPath> before = route.chooser.chosen();
    route.chooser.offer(livePaths(route, dest, *session));
    const std::optional<RawPathChooser::Probe> probe = route.chooser.probe(now);
    reportPath(host, route.chooser, before);
    if (probe.has_value())
    {
        sendProbe(datagram, session, route, kept, probe.value());
    }
}

void EmbeddedEndpoint::answerPathProbe(const ByteView frame)
{
    if (frame.size() != kPathProbeBytes || !datagram)
    {
        return;
    }
    const std::uint64_t id = bufbe64toh(frame.subspan(kPathProbeIdOffset).data());
    const auto now = std::chrono::steady_clock::now();
    if (frame[0] == kPathEcho)
    {
        for (auto& [host, route] : rawTargets->routes)
        {
            const std::optional<RawPath> before = route.chooser.chosen();
            if (route.chooser.echoed(id, now))
            {
                reportPath(host, route.chooser, before);
                return;
            }
        }
        return;
    }
    if (frame[0] != kPathProbe)
    {
        return;
    }
    std::vector<std::uint8_t> echo(frame.begin(), frame.end());
    echo[0] = kPathEcho;
    for (const auto& [host, route] : rawTargets->routes)
    {
        if (now - route.lastSent <= kPathPeerActive)
        {
            sendOnRoute(*datagram, datagram->GetSession(route.ident), route, echo, kPathProbePort);
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
    std::optional<DestinationDetail> destinationDetail(const std::string& host) const override;
    LeaseSetRefresh refreshLeaseSet(
        const std::string& localHost, const std::string& remoteHost) override;
    void setSocksProxy(const std::string& host, int port) override;
    ProxyState proxyState() const override;
    void setReseedUrls(const std::vector<std::string>& urls) override;
    ReseedState reseedState() const override;
    std::shared_ptr<backend::EndpointBackend> createEndpoint(const EndpointConfig& config) override;
    void retagEndpoint(const backend::EndpointBackend& endpoint, std::string label,
        std::string accountLabel) override;

    bool owns = false;
    bool inited = false;
    mutable std::mutex lifecycleMutex;
    bool started = false;
    std::string builtInReseedUrls;
    std::shared_ptr<IoService> io;

    struct DestEntry {
        std::weak_ptr<i2pd::client::ClientDestination> dest;
        std::shared_ptr<DestTag> tag;
        std::string host;
        bool published = false;
    };
    mutable std::mutex destsMutex;
    mutable std::vector<DestEntry> dests;

    struct HeldDest {
        DestEntry entry;
        std::shared_ptr<i2pd::client::ClientDestination> dest;
    };
    std::optional<HeldDest> heldDest(const std::string& host) const;
    static LocalDestination describe(
        const DestEntry& entry, const i2pd::client::ClientDestination& dest);

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

std::string reseedUrlList(const std::vector<std::string>& reseedUrls)
{
    std::string list;
    for (const std::string& url : reseedUrls)
    {
        if (!isReseedUrl(url))
        {
            throw std::invalid_argument("i2p: a reseed is an https URL (" + url + ")");
        }
        list += (list.empty() ? "" : ",") + url;
        if (list.back() != '/')
        {
            list += '/';
        }
    }
    return list;
}

}  // namespace

EmbeddedRouter::EmbeddedRouter(const RouterConfig& config)
{
    (void)reseedUrlList(config.reseedUrls);

    bool expected = false;
    if (!g_routerLive.compare_exchange_strong(expected, true))
    {
        throw std::runtime_error("bazarish::i2p::Router: only one router per process");
    }
    owns = true;

    std::vector<std::string> args;
    args.push_back("bazarish-i2p");
    args.push_back("--datadir=" + config.dataDir.string());
    args.push_back("--loglevel=warn");
    args.push_back("--persist.profiles=false");

    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) { argv.push_back(arg.data()); }

    i2pd::api::InitI2P(static_cast<int>(argv.size()), argv.data(), "bazarish-i2p");
    inited = true;
    // libi2pd parses transit and bandwidth options but only the i2pd daemon applies them.
    const bool server = config.role == Role::eServer;
    i2pd::context.SetAcceptsTunnels(server);
    if (server)
    {
        i2pd::context.SetBandwidth(i2pd::data::CAPS_FLAG_EXTRA_BANDWIDTH2);
        i2pd::context.SetShareRatio(kServerShareRatio);
    }
    bazarish::log::info("i2p: engine initialised");
    i2pd::config::GetOption("reseed.urls", builtInReseedUrls);
    if (!i2pd::config::SetOption("reseed.file", config.reseedFile.string()))
    {
        throw std::runtime_error("bazarish::i2p: this engine has no reseed option to set");
    }
    setReseedUrls(config.reseedUrls);
    setSocksProxy(config.socksProxyHost, config.socksProxyPort);
    start();
}

void EmbeddedRouter::start()
{
    const std::lock_guard<std::mutex> lock(lifecycleMutex);
    if (started) { return; }
    i2pd::api::StartI2P([](LogLevel level, const std::string& text)
    {
        if (level == eLogNone || level > i2pdLevelOf(i2pLogLevel())) { return; }
        bazarish::log::emit(mapLevel(level), text);
    });
    backend::setEmbeddedLogLevel(i2pLogLevel());
    started = true;
    bazarish::log::info("i2p: engine running");
    io = std::make_shared<IoService>(ioContextCount());
}

void EmbeddedRouter::setReseedUrls(const std::vector<std::string>& urls)
{
    const std::string listed = reseedUrlList(urls);
    if (!i2pd::config::SetOption("reseed.urls", listed.empty() ? builtInReseedUrls : listed))
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
    const std::lock_guard<std::mutex> lock(lifecycleMutex);
    if (!started) { return; }
    io.reset();
    i2pd::api::StopI2P();
    started = false;
}

bool EmbeddedRouter::running() const
{
    const std::lock_guard<std::mutex> lock(lifecycleMutex);
    return started;
}

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
    const auto patience = std::chrono::seconds(kSessionSnapshotSeconds);
    // i2pd hands the server out const; the object is not, and its table lives on its service.
    if (auto* const ntcp2 = const_cast<i2pd::transport::NTCP2Server*>(
            i2pd::transport::transports.GetNTCP2Server())) {
        using Sessions = std::decay_t<decltype(ntcp2->GetNTCP2Sessions())>;
        const auto taken = std::make_shared<std::promise<Sessions>>();
        std::future<Sessions> copy = taken->get_future();
        boost::asio::post(
            ntcp2->GetService(), [ntcp2, taken]() { taken->set_value(ntcp2->GetNTCP2Sessions()); });
        if (copy.wait_for(patience) == std::future_status::ready) {
            collect(copy.get(), "NTCP2");
        }
    }
    if (auto* const ssu2 = i2pd::transport::transports.GetSSU2Server()) {
        const auto sessions = std::make_shared<i2pd::transport::SSU2Server::SSU2Sessions>();
        std::future<void> copied = ssu2->GetSSU2Sessions(*sessions);
        boost::asio::post(ssu2->GetService(), [sessions]() {});
        if (copied.wait_for(patience) == std::future_status::ready) {
            collect(*sessions, "SSU2");
        }
    }
    return peers;
}

void EmbeddedRouter::retagEndpoint(
    const backend::EndpointBackend& endpoint, std::string label, std::string accountLabel)
{
    static_cast<const EmbeddedEndpoint&>(endpoint).tag->retag(
        std::move(label), std::move(accountLabel));
}

LocalDestination EmbeddedRouter::describe(
    const DestEntry& entry, const i2pd::client::ClientDestination& dest)
{
    constexpr int kTunnelCountProbe = 64;
    LocalDestination info;
    info.label = entry.tag->label();
    info.accountLabel = entry.tag->accountLabel();
    info.host = entry.host;
    info.published = entry.published;
    info.ready = dest.IsReady();
    info.remoteLeaseSets = dest.GetNumRemoteLeaseSets();
    const auto tunnelPool = dest.GetTunnelPool();
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
    return info;
}

std::vector<LocalDestination> EmbeddedRouter::localDestinations() const
{
    std::vector<LocalDestination> live;
    std::lock_guard<std::mutex> lock(destsMutex);
    std::erase_if(dests, [](const DestEntry& entry) { return entry.dest.expired(); });
    for (const DestEntry& entry : dests) {
        const std::shared_ptr<i2pd::client::ClientDestination> dest = entry.dest.lock();
        if (!dest) { continue; }
        live.push_back(describe(entry, *dest));
    }
    return live;
}

std::optional<EmbeddedRouter::HeldDest> EmbeddedRouter::heldDest(const std::string& host) const
{
    const std::lock_guard<std::mutex> lock(destsMutex);
    for (const DestEntry& entry : dests) {
        if (entry.host != host) { continue; }
        if (std::shared_ptr<i2pd::client::ClientDestination> dest = entry.dest.lock()) {
            return HeldDest{entry, std::move(dest)};
        }
    }
    return std::nullopt;
}

namespace {

constexpr std::size_t kHopHashChars = 6;
constexpr char kB32Suffix[] = ".b32.i2p";

TunnelState tunnelStateOf(const i2pd::tunnel::TunnelState state)
{
    switch (state)
    {
        case i2pd::tunnel::eTunnelStatePending:
        case i2pd::tunnel::eTunnelStateBuildReplyReceived: return TunnelState::eBuilding;
        case i2pd::tunnel::eTunnelStateEstablished: return TunnelState::eEstablished;
        case i2pd::tunnel::eTunnelStateExpiring: return TunnelState::eExpiring;
        case i2pd::tunnel::eTunnelStateBuildFailed:
        case i2pd::tunnel::eTunnelStateTestFailed:
        case i2pd::tunnel::eTunnelStateFailed: return TunnelState::eFailed;
    }
    return TunnelState::eFailed;
}

TunnelDetail describeTunnel(const i2pd::tunnel::Tunnel& tunnel, const std::size_t bytes)
{
    TunnelDetail detail;
    detail.inbound = tunnel.IsInbound();
    for (const auto& hop : tunnel.GetPeers()) {
        if (hop) {
            detail.hops.push_back(hop->GetIdentHash().ToBase64().substr(0, kHopHashChars));
        }
    }
    detail.state = tunnelStateOf(tunnel.GetState());
    if (tunnel.LatencyIsKnown()) {
        detail.latencyMs = tunnel.GetMeanLatency();
    }
    detail.bytes = bytes;
    return detail;
}

std::string remoteHostOf(const i2pd::data::LeaseSet& leaseSet)
{
    if (leaseSet.IsPublishedEncrypted()) {
        return i2pd::data::BlindedPublicKey(leaseSet.GetIdentity()).ToB33() + kB32Suffix;
    }
    return leaseSet.GetIdentHash().ToBase32() + kB32Suffix;
}

bool hasIdentity(const std::shared_ptr<i2pd::data::LeaseSet>& leaseSet)
{
    return leaseSet && leaseSet->GetIdentity();
}

LeaseSetSeen seenOf(const i2pd::data::LeaseSet& leaseSet)
{
    LeaseSetSeen seen;
    seen.publishedAt = static_cast<std::int64_t>(leaseSet.GetPublishedTimestamp());
    seen.expiresAt = static_cast<std::int64_t>(leaseSet.GetExpirationTime()) / kMillisPerSecond;
    return seen;
}

// One of the two names a lease set is looked up by.
struct LookupTarget {
    std::optional<i2pd::data::IdentHash> ident;
    std::shared_ptr<i2pd::data::BlindedPublicKey> blinded;
};

std::optional<LookupTarget> lookupTargetOf(const std::string& host)
{
    LookupTarget target;
    if (!isB32I2pHost(host)) {
        i2pd::data::IdentityEx identity;
        if (identity.FromBase64(host) == 0) {
            return std::nullopt;
        }
        target.ident = identity.GetIdentHash();
        return target;
    }
    const std::string label = host.substr(0, host.size() - kB32SuffixLen);
    std::array<std::uint8_t, kB32LabelBytesMax> raw{};
    if (i2pd::data::Base32ToByteStream(label, raw.data(), raw.size()) == kIdentHashBytes) {
        target.ident = i2pd::data::IdentHash(raw.data());
        return target;
    }
    target.blinded = std::make_shared<i2pd::data::BlindedPublicKey>(std::string_view(label));
    return target;
}

std::vector<RemoteLeaseSet> remoteLeaseSetsOf(const i2pd::client::ClientDestination& dest)
{
    const std::int64_t now = static_cast<std::int64_t>(i2pd::util::GetMillisecondsSinceEpoch());
    // An encrypted lease set is kept under its identity and under each day's blinded key.
    std::map<std::string, RemoteLeaseSet> byHost;
    for (const auto& leaseSet : dest.GetLeaseSetsList()) {
        if (!hasIdentity(leaseSet)) { continue; }
        RemoteLeaseSet entry;
        entry.host = remoteHostOf(*leaseSet);
        entry.expiresIn = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds(
            static_cast<std::int64_t>(leaseSet->GetExpirationTime()) - now));
        entry.leases = static_cast<int>(leaseSet->GetNonExpiredLeases(false).size());
        const auto [held, added] = byHost.try_emplace(entry.host, entry);
        if (!added && held->second.expiresIn < entry.expiresIn) {
            held->second = std::move(entry);
        }
    }
    std::vector<RemoteLeaseSet> listed;
    listed.reserve(byHost.size());
    for (auto& [host, entry] : byHost) { listed.push_back(std::move(entry)); }
    return listed;
}

template <typename Work>
auto onDestinationThread(i2pd::client::ClientDestination& dest, Work work)
{
    using Result = decltype(work());
    const auto taken = std::make_shared<std::promise<Result>>();
    std::future<Result> result = taken->get_future();
    boost::asio::post(dest.GetService(), [taken, work = std::move(work)]() { taken->set_value(work()); });
    if (result.wait_for(std::chrono::seconds(kSessionSnapshotSeconds)) != std::future_status::ready) {
        throw std::runtime_error("bazarish::i2p: the destination's thread did not answer in time");
    }
    return result.get();
}

}  // namespace

std::optional<DestinationDetail> EmbeddedRouter::destinationDetail(const std::string& host) const
{
    const std::optional<HeldDest> held = heldDest(host);
    if (!held.has_value()) {
        return std::nullopt;
    }
    DestinationDetail detail;
    detail.destination = describe(held->entry, *held->dest);
    if (const auto pool = held->dest->GetTunnelPool()) {
        for (const auto& tunnel : pool->GetInboundTunnelsList()) {
            if (tunnel) {
                detail.tunnels.push_back(describeTunnel(*tunnel, tunnel->GetNumReceivedBytes()));
            }
        }
        for (const auto& tunnel : pool->GetOutboundTunnelsList()) {
            if (tunnel) {
                detail.tunnels.push_back(describeTunnel(*tunnel, tunnel->GetNumSentBytes()));
            }
        }
    }
    const std::shared_ptr<i2pd::client::ClientDestination> dest = held->dest;
    detail.leaseSets = onDestinationThread(*dest, [dest]() { return remoteLeaseSetsOf(*dest); });
    return detail;
}

LeaseSetRefresh EmbeddedRouter::refreshLeaseSet(
    const std::string& localHost, const std::string& remoteHost)
{
    const std::optional<HeldDest> held = heldDest(localHost);
    if (!held.has_value()) {
        throw std::runtime_error("bazarish::i2p: no destination " + localHost + " to look up from");
    }
    const auto answered = std::make_shared<std::promise<LeaseSetRefresh>>();
    std::future<LeaseSetRefresh> answer = answered->get_future();
    const std::shared_ptr<i2pd::client::ClientDestination> dest = held->dest;
    boost::asio::post(dest->GetService(), [dest, remoteHost, answered]() {
        LeaseSetRefresh refresh;
        std::vector<std::shared_ptr<i2pd::data::LeaseSet>> cached;
        for (const auto& leaseSet : dest->GetLeaseSetsList()) {
            if (hasIdentity(leaseSet) && remoteHostOf(*leaseSet) == remoteHost) {
                cached.push_back(leaseSet);
                const LeaseSetSeen seen = seenOf(*leaseSet);
                if (!refresh.before.has_value() || publishedLater(seen, refresh.before)) {
                    refresh.before = seen;
                }
            }
        }
        const auto done = [answered, refresh](const std::shared_ptr<i2pd::data::LeaseSet>& found) {
            LeaseSetRefresh told = refresh;
            if (found && !found->IsExpired()) {
                told.after = seenOf(*found);
            }
            answered->set_value(told);
        };
        const std::optional<LookupTarget> target = lookupTargetOf(remoteHost);
        if (!target.has_value()) {
            done(nullptr);
            return;
        }
        if (target->ident.has_value()) {
            (void)dest->RequestDestination(*target->ident, done);
            return;
        }
        // A lookup by blinded key answers from the cache while the cached copy is current.
        for (const auto& leaseSet : cached) {
            leaseSet->ExpireLease();
        }
        (void)dest->RequestDestinationWithEncryptedLeaseSet(target->blinded, done);
    });
    return answer.get();
}

std::shared_ptr<backend::EndpointBackend> EmbeddedRouter::createEndpoint(
    const EndpointConfig& config)
{
    const Keys keys = config.keys.has_value() ? config.keys.value() : Keys::generate();

    auto impl = std::make_shared<EmbeddedEndpoint>();
    impl->tag = std::make_shared<DestTag>(config.label, config.accountLabel);
    impl->publicDestination = keys.publicBase64();
    impl->hostAddress = bazarish::i2p::routingHost(impl->publicDestination, config.blinded);

    i2pd::util::Mapping params;
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_TYPE,
        std::to_string(config.blinded ? i2pd::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2
                                      : i2pd::data::NETDB_STORE_TYPE_STANDARD_LEASESET2));
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_ENCRYPTION_TYPE, "4");
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_PERSIST_KEYS, "false");
    if (!config.leaseSetReaders.empty()) {
        params.Insert(i2pd::client::I2CP_PARAM_LEASESET_AUTH_TYPE,
            std::to_string(i2pd::data::ENCRYPTED_LEASESET_AUTH_TYPE_DH));
        for (std::size_t index = 0; index < config.leaseSetReaders.size(); ++index) {
            const std::string name = "r" + std::to_string(index);
            params.Insert(std::string(i2pd::client::I2CP_PARAM_LEASESET_CLIENT_DH) + "." + name,
                name + ":" + backend::leaseSetKeyBase64(config.leaseSetReaders[index]));
        }
    }
    if (!config.leaseSetReaderKey.empty()) {
        params.Insert(i2pd::client::I2CP_PARAM_LEASESET_PRIV_KEY,
            backend::leaseSetKeyBase64(config.leaseSetReaderKey));
    }
    const TunnelLength length = tunnelLengthFor(config.privacy);
    params.Insert(i2pd::client::I2CP_PARAM_INBOUND_TUNNEL_LENGTH, std::to_string(length.hops));
    params.Insert(i2pd::client::I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH, std::to_string(length.hops));
    params.Insert(i2pd::client::I2CP_PARAM_INBOUND_TUNNELS_LENGTH_VARIANCE, std::to_string(length.variance));
    params.Insert(i2pd::client::I2CP_PARAM_OUTBOUND_TUNNELS_LENGTH_VARIANCE, std::to_string(length.variance));
    const int quantity = std::clamp(config.tunnelQuantity, 1, 16);
    params.Insert(i2pd::client::I2CP_PARAM_INBOUND_TUNNELS_QUANTITY, std::to_string(quantity));
    params.Insert(i2pd::client::I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY, std::to_string(quantity));

    {
        const std::lock_guard<std::mutex> lock(lifecycleMutex);
        if (!started) {
            throw std::runtime_error("bazarish::i2p: the engine is not running");
        }
        impl->io = io;
    }
    impl->dest = std::make_shared<i2pd::client::ClientDestination>(
        config.realtime ? impl->io->reserved() : impl->io->next(),
        parseKeys(keys.blob()), config.published, &params);
    impl->dest->Start();
    {
        std::lock_guard<std::mutex> lock(destsMutex);
        std::erase_if(dests,
            [](const DestEntry& entry) { return entry.dest.expired(); });
        dests.push_back(DestEntry{impl->dest, impl->tag, impl->hostAddress, config.published});
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
    if (config.realtime)
    {
        impl->rawTargets->steered = true;
        impl->datagram->SetRawReceiver([weak](std::uint16_t, std::uint16_t,
            const std::uint8_t* buf, std::size_t len)
        {
            const std::shared_ptr<EmbeddedEndpoint> held = weak.lock();
            if (held) { held->answerPathProbe(ByteView(buf, len)); }
        }, kPathProbePort);
    }

    return impl;
}

Capabilities EmbeddedRouter::capabilities() const
{
    Capabilities what;
    what.routerCounters = true;
    what.destinationCounters = true;
    what.netDbSample = true;
    what.proxy = true;
    what.lateReaderKey = true;
    what.offlineKeys = true;
    what.reseed = true;
    what.destinationDetail = true;
    what.leaseSetRefresh = true;
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

Bytes keysBlobFromSeeds(const Bytes& signingSeed, const Bytes& cryptoSeed)
{
    if (signingSeed.size() != kRawKeyBytes || cryptoSeed.size() != kRawKeyBytes)
    {
        throw std::invalid_argument("bazarish::i2p: a key seed is 32 bytes");
    }
    ensureCryptoInit();
    const Bytes signingPublic = rawPublicOf(EVP_PKEY_ED25519, signingSeed);
    const Bytes cryptoPublic = rawPublicOf(EVP_PKEY_X25519, cryptoSeed);
    const i2pd::data::IdentityEx identity(
        cryptoPublic.data(), signingPublic.data(), kSigType, kSeededCryptoType);
    Bytes blob(identity.GetFullLen());
    if (identity.ToBuffer(blob.data(), blob.size()) != blob.size())
    {
        throw std::runtime_error("bazarish::i2p: the identity did not serialize");
    }
    // i2pd pads both key fields at random; a derived destination pads them with zeros.
    std::fill(blob.begin() + kRawKeyBytes,
        blob.begin() + kSigningFieldOffset + kSigningFieldBytes - kRawKeyBytes, 0);
    blob.insert(blob.end(), cryptoSeed.begin(), cryptoSeed.end());
    blob.insert(blob.end(), signingSeed.begin(), signingSeed.end());
    Bytes keys = serializeKeys(parseKeys(blob));
    OPENSSL_cleanse(blob.data(), blob.size());
    return keys;
}

std::optional<std::int64_t> offlineExpires(const Bytes& blob)
{
    const i2pd::data::PrivateKeys keys = parseKeys(blob);
    if (!keys.IsOfflineSignature()) {
        return std::nullopt;
    }
    const std::vector<std::uint8_t>& signature = keys.GetOfflineSignature();
    if (signature.size() < i2pd::data::OFFLINE_SIGNATURE_HEADER_LENGTH) {
        throw std::runtime_error("bazarish::i2p: truncated offline signature");
    }
    return static_cast<std::int64_t>(bufbe32toh(signature.data()));
}

bool b33OfflineKeysCover(const Bytes& blob, const std::int64_t fromUnix, const std::int64_t untilUnix)
{
    const i2pd::data::PrivateKeys keys = parseKeys(blob);
    const std::int64_t firstDay
        = (fromUnix / i2pd::data::SECONDS_PER_DAY) * i2pd::data::SECONDS_PER_DAY;
    for (std::int64_t day = firstDay; day < untilUnix; day += i2pd::data::SECONDS_PER_DAY) {
        std::array<char, kDateStringBytes> date{};
        i2pd::util::GetDateString(static_cast<std::uint64_t>(day), date.data());
        if (!i2pd::data::OfflinePrivateKeys(keys, date.data()).IsOfflineSignature()) {
            return false;
        }
    }
    return true;
}

}  // namespace backend

}  // namespace bazarish::i2p
