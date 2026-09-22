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

// Reach the embedded i2pd engine. Inside namespace bazarish::i2p the bare name
// "i2p" resolves to our own namespace, so the engine must be addressed through
// this alias.
namespace i2pd = ::i2p;

namespace bazarish::i2p {
namespace {

constexpr i2pd::data::SigningKeyType kSigType = i2pd::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519;
// The outer layer of an encrypted LeaseSet is signed under a blinded key, and
// blinding yields a scalar - which is what RedDSA's private key already is.
constexpr i2pd::data::SigningKeyType kB33SigType
    = i2pd::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519;
// The batch counts its days in two bytes, which is the ceiling on a delegation.
constexpr int kMaxB33Days = 0xFFFF;
constexpr std::size_t kB32SuffixLen = 8;  // ".b32.i2p"
// How long one receive waits on the engine before the caller looks up again:
// long enough not to spin, short enough that a closed stream and an expired read
// deadline are both noticed promptly.
constexpr int kReceivePollSeconds = 5;
// How long to wait for a transport server to hand back a snapshot of its
// session map; it is answered on that server's own service thread.
constexpr int kSessionSnapshotSeconds = 2;
// One round of asking the network for a destination, and how finely that round is
// waited out so a stopped endpoint is noticed inside it. The pause is what
// separates two rounds when the first came back empty.
constexpr int kDialRoundMillis = 30000;
constexpr int kDialSliceMillis = 250;
constexpr int kDialRetryPauseMillis = 2000;

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

// The start of the current UTC day. The b33 batch holds one key per day, so a
// delegation covers whole days counted from here and ends at a midnight.
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

// The b33 offline keys that let a server publish this destination as an encrypted
// LeaseSet2 without holding its signing key: one transient per day, each
// authorized by the blinded key of its own day. Generation lives here because
// libi2pd only reads the batch; the primitives are its own.
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
        // Blinding the transient of an existing delegation yields a key the
        // address does not belong to, and a LeaseSet nobody can read.
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
        // The first two fields are byte for byte the offline block of the LeaseSet.
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
        // The blinded private key would give the destination's own key away: alpha
        // is derived from public data, so subtracting it recovers the master.
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
    // The first lane is not handed out here: it is kept for real-time media (see
    // reserved()), because a lane is one thread and a file moving on it is a
    // call stuttering on it. With a single lane there is nothing to keep apart
    // and everything shares it.
    boost::asio::io_context& next()
    {
        if (lanes_.size() == 1) {
            return lanes_.front()->ctx;
        }
        const std::size_t i
            = 1 + nextLane_.fetch_add(1, std::memory_order_relaxed) % (lanes_.size() - 1);
        return lanes_[i]->ctx;
    }

    // The lane kept for real-time media. Calls are the only thing on it, and a
    // call has one media destination at a time, so it is a lane with one
    // destination on it for as long as the call lasts.
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

// Number of lanes (single-threaded io_contexts) for the destination pool: half
// the hardware concurrency, clamped to [2, 8]. The destination layer (streaming,
// datagrams, leaseset/garlic handling) runs here alongside the i2pd engine's own
// transport and tunnel threads, so a fraction of the cores is plenty and leaves
// headroom for the engine. One of them is kept for real-time media and the rest
// carry everything else, which is why the floor is two rather than one.
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

}  // namespace

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

std::string backend::embeddedRouterVersion()
{
    // The upstream i2pd version baked into the embedded engine (e.g. "2.60.0").
    return I2PD_VERSION;
}

std::vector<Bytes> backend::embeddedSampleRouterInfos(const std::size_t count)
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

std::size_t backend::embeddedSeedRouterInfos(
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

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

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
    // The destination this stream belongs to, held for as long as the stream is.
    // Closing is posted to that destination's service, so letting the
    // destination go first would leave the close to run against a torn-down
    // streaming layer.
    std::shared_ptr<i2pd::client::ClientDestination> owner;
    // Raised when the whole destination is stopped, and shared with it: a read
    // must end when the endpoint is told to give up, not only when this one
    // stream is closed.
    std::shared_ptr<std::atomic<bool>> stopped;
    std::atomic<bool> closed{false};
    // Zero waits for as long as the stream is open.
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
        // Otherwise a poll timeout on a stream the engine still calls open. That
        // is also what a stream whose far side has gone away looks like - the
        // close travels through tunnels and need not arrive - so a caller that
        // set a deadline is told rather than left waiting on it.
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
    // Two queues, not one: bytes still in the send buffer, and packets already
    // sent that the far side has not acknowledged. Counting only the first made a
    // sender's progress run far ahead of the receiver's, because the engine
    // drains the buffer into its unacknowledged window immediately. The in-flight
    // half is an upper bound (packet count times the streaming MTU), so progress
    // errs behind rather than ahead.
    return stream->GetSendBufferSize()
        + stream->GetSendQueueSize() * i2pd::stream::STREAMING_MTU;
}

void EmbeddedStream::close()
{
    if (stream && !closed.exchange(true))
    {
        // Asynchronously, which is what the engine requires of every thread but
        // the destination's own - and what makes "write, then close" mean it. A
        // write is queued onto that same service; closing from this thread runs
        // first, finds the send buffer still empty and puts the close packet on
        // the wire ahead of the data, so the last thing written never leaves.
        // That is a federation reply the far side is waiting for.
        stream->AsyncClose();
    }
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

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

    // Raised once, by stop(). Every wait this endpoint owns watches it, and so do
    // the streams it handed out - which is what lets a thread be taken out of a
    // dial that still has a minute of deadline to spend. Held by shared_ptr
    // because a stream outlives the call that made it and may outlive nothing
    // else of this endpoint.
    std::shared_ptr<std::atomic<bool>> stopped = std::make_shared<std::atomic<bool>>(false);

    // Keeps the router's shared service alive for as long as this endpoint (and its
    // destination's reference to the io_context) exists. Declared first so it is
    // destroyed last, after dest below.
    std::shared_ptr<IoService> io;
    std::shared_ptr<i2pd::client::ClientDestination> dest;
    std::shared_ptr<i2pd::datagram::DatagramDestination> datagram;

    // What this destination is for, as the caller named it: only ever used to say
    // which one a log line is about.
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

    // Where raw datagrams go, once. A blinded (b33) address is not the hash it
    // routes to: it has to be looked up, and call media sends fifty datagrams a
    // second - one lookup each is a lookup storm, and every packet sent before
    // the first answer arrives is a packet that never left.
    //
    // Held by shared_ptr because the answer arrives on an engine thread and the
    // call it belongs to may be over by then: the lookup writes into this, never
    // into the endpoint.
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
    // Stop the destination on the lane that services it, holding it alive until
    // that runs. Releasing it from this thread stops it while the lane may still
    // be sending queued packets, and the streaming layer it tears down is read by
    // that very handler - a use-after-free ASAN catches in
    // Stream::SendPackets -> StreamingDestination::GetOwner().
    const std::shared_ptr<i2pd::client::ClientDestination> closing = dest;
    bazarish::log::info("i2p: closing destination {} ({})",
        label.empty() ? std::string("unnamed") : label, hostAddress);
    // Streams accepted but never taken belong to that same lane: it may be
    // sending on them at this moment. Dropping the last reference here destroys
    // them under the lane's feet, and the lane then writes through what it is
    // holding - a crash inside Stream::SendPackets, seen while an account was
    // being closed. They go back to the lane with the destination.
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
            // Held across the stop. Stopping a destination drops its streaming
            // destination, and every stream still queued on this lane reaches
            // its owner through a reference to that object - not a pointer it
            // could check - so freeing it here is read back by the next queued
            // packet. AddressSanitizer names it exactly: freed in
            // ClientDestination::Stop, read in Stream::SendPackets ->
            // StreamingDestination::GetOwner.
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
            // Everything those streams left on this lane runs before this last
            // handler, and the references go with it - after the lane has
            // nothing of theirs left to run.
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
    // The waiters are asleep on their own condition variables, and the flag alone
    // does not reach them: each is woken so its predicate is looked at again.
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
    // Resolve the target once into a request issuer (b32 ident, b33 blinded key,
    // or a raw base64 destination).
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

    // Retry the lookup-and-connect until the deadline: a freshly published remote
    // LeaseSet can lag the remote's readiness, so one attempt may miss it.
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
        // Waited for in slices so stop() is noticed while a round is still in the
        // air: the deadline is a minute, and a caller that has given up must not
        // be held for the rest of it.
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
                std::chrono::milliseconds(kDialRetryPauseMillis));  // failed round; re-request
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
    if (acceptQueue.empty()) { return nullptr; }  // woken by stop()
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
            // Encrypted-LS peer: resolve the blinded leaseset, then send (best-effort).
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
            // A blinded address. Looked up once and remembered: what follows is a
            // stream of media, not one message.
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
                    return;  // a lookup is already out; this datagram waits for nobody
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
                        // Said out loud: without it a call with nothing to route
                        // to is a call with no sound and no reason given.
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

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

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
    Keys generateKeys() override;
    std::shared_ptr<backend::EndpointBackend> createEndpoint(const EndpointConfig& config) override;
    void retagEndpoint(
        const backend::EndpointBackend& endpoint, std::string label, std::string owner) override;

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
    // Swept while reporting, which is the only time anyone looks.
    mutable std::vector<DestEntry> dests;

    ~EmbeddedRouter()
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

EmbeddedRouter::EmbeddedRouter(const RouterConfig& config)
{
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
    // Peer profiles are a plain-text record of which routers this installation
    // has been talking to, and when. Keeping them buys a little tunnel-building
    // quality; leaving them on disk costs a log of the user's activity.
    args.push_back("--persist.profiles=false");
    if (!config.reseedUrls.empty())
    {
        // The addresses this router bootstraps from, in place of the engine's
        // built-in list. Each is a reseed base - the same shape every public
        // reseed has - and the engine appends the archive's standard name to it,
        // fetches it with the user agent every I2P router sends, unpacks it and
        // loads the routers, each of which carries its own signature and is
        // verified on load. The su3's own signature is not required
        // (reseed.verify is off by default): a private reseed is signed by nobody
        // a stock client trusts, so requiring it would mean no private reseeds.
        // The trailing slash is put back if it is missing, because the engine
        // concatenates rather than joins.
        std::string joined;
        for (const std::string& url : config.reseedUrls)
        {
            if (url.rfind("https://", 0) != 0)
            {
                // Not an address but an archive already on disk: an offline
                // install, or a test feeding the engine a file it packed itself.
                args.push_back("--reseed.file=" + url);
                continue;
            }
            joined += (joined.empty() ? "" : ",") + url;
            if (joined.back() != '/')
            {
                joined += '/';
            }
        }
        if (!joined.empty())
        {
            args.push_back("--reseed.urls=" + joined);
        }
    }

    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) { argv.push_back(arg.data()); }

    i2pd::api::InitI2P(static_cast<int>(argv.size()), argv.data(), "bazarish-i2p");
    inited = true;
    // After the config is parsed and before the transports come up, which is when
    // they read it.
    setSocksProxy(config.socksProxyHost, config.socksProxyPort);
    start();
}

void EmbeddedRouter::start()
{
    if (started) { return; }
    i2pd::api::StartI2P();
    // StartI2P always (re)points logging, so install our sink after it (on every
    // start - it is reset each time). The sink drops everything unless logging was
    // explicitly turned on, so by default the embedded router is silent.
    i2pd::log::Logger().SendTo([](LogLevel level, const std::string& text)
    {
        if (!i2pLogging()) { return; }
        bazarish::log::emit(mapLevel(level), text);
    });
    // Honor the current logging setting (default OFF) now that the logger exists,
    // so the engine does not even format messages while logging is suppressed.
    i2pd::log::Logger().SetLogLevel(i2pLogging() ? "warn" : "none");
    started = true;
    io = std::make_shared<IoService>(ioContextCount());
}

void EmbeddedRouter::setSocksProxy(const std::string& host, const int port)
{
    const bool wanted = !host.empty() && port > 0;
    const std::string url
        = wanted ? "socks://" + host + ":" + std::to_string(port) : std::string();
    i2pd::config::SetOption("ntcp2.proxy", url);
    i2pd::config::SetOption("reseed.proxy", url);
    // SSU2 goes off whenever a proxy is set, without exception. Its datagrams can
    // only ride SOCKS5's UDP ASSOCIATE, which most proxies do not offer and which
    // i2pd attempts against a literal address alone - and whatever the proxy does
    // not carry, SSU2 sends straight out around it. NTCP2 carries the router on
    // its own; nothing leaves unproxied.
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
    // Release the shared service before stopping the engine: workers must drain and
    // join while the engine they post to is still up.
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
    if (auto* const ssu2 = i2pd::transport::transports.GetSSU2Server()) {
        // The SSU2 session map may only be read on the server's own service, which
        // hands the snapshot back through a future.
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
    // More than any pool can hold: the quantity is clamped to 16 per direction,
    // so this asks for every established inbound tunnel there can be.
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
        // A stopped destination keeps its pool until the last handler holding it
        // returns, and the pool stands down the moment it is stopped: that flag is
        // the difference between an address coming up and one going away.
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
    auto impl = std::make_shared<EmbeddedEndpoint>();
    impl->label = config.label;
    impl->publicDestination = config.keys.publicBase64();
    impl->hostAddress = bazarish::i2p::routingHost(impl->publicDestination);
    impl->keysBlob = config.keys.blob();

    i2pd::util::Mapping params;
    params.Insert(i2pd::client::I2CP_PARAM_LEASESET_TYPE,
        std::to_string(i2pd::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2));
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
    impl->io = io;
    impl->dest = std::make_shared<i2pd::client::ClientDestination>(
        config.realtime ? impl->io->reserved() : impl->io->next(),
        parseKeys(config.keys.blob()), config.published, &params);
    impl->dest->Start();
    {
        std::lock_guard<std::mutex> lock(destsMutex);
        std::erase_if(dests,
            [](const DestEntry& entry) { return entry.dest.expired(); });
        dests.push_back(DestEntry{
            impl->dest, config.label, config.owner, impl->hostAddress, config.published});
    }

    // Weakly, and never by raw pointer: these callbacks live on the engine's own
    // threads and can fire while this endpoint is being torn down. A weak
    // reference that no longer locks is the difference between doing nothing and
    // writing into freed memory.
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
    // The engine is in this process, so everything about it can be answered.
    Capabilities what;
    what.routerCounters = true;
    what.destinationCounters = true;
    what.netDbSample = true;
    what.proxy = true;
    what.offlineKeys = true;
    return what;
}

Keys EmbeddedRouter::generateKeys()
{
    return Keys::fromBlob(backend::generateKeysBlob());
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
    // One reading of the clock for the whole delegation: taken twice, a day
    // change between them would end the inner transient a day before the batch.
    const std::uint64_t midnight = currentMidnight();
    // The transient of the inner LeaseSet lasts exactly as long as the batch.
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
    // A batch that cannot sign today is no better than none: say so now rather
    // than at the first publication, which has no caller left to tell.
    char today[9];
    i2pd::util::GetDateString(currentMidnight(), today);
    if (!i2pd::data::OfflinePrivateKeys(keys, today).IsOfflineSignature()) { return 0; }
    return bufbe16toh(batch.GetBuffer() + i2pd::data::B33_OFFLINE_KEYS_HEADER_LENGTH - 2);
}

}  // namespace backend

}  // namespace bazarish::i2p
