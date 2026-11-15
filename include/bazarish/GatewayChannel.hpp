// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/KeyedSeal.hpp"
#include "bazarish/SecretBytes.hpp"
#include "bazarish/TrafficShape.hpp"
#include "bazarish/WebSocket.hpp"
#include "bazarish/WebSocketClient.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::gateway {

inline constexpr std::size_t kTicketBytes = 16;
inline constexpr std::size_t kTicketsHeld = 8;
inline constexpr std::size_t kSessionKeyBytes = kAeadKeyBytes;
inline constexpr std::size_t kHandshakePadMin = 64;
inline constexpr std::size_t kHandshakePadMax = 4096;
inline constexpr std::chrono::seconds kHandshakeTimeout{30};

inline constexpr std::size_t kRecordFlagsBytes = 1;
inline constexpr std::size_t kRecordLengthBytes = 2;
inline constexpr std::size_t kRecordHeaderBytes = kRecordFlagsBytes + kRecordLengthBytes;
inline constexpr std::uint8_t kRecordActive = 0x01;
inline constexpr double kRecordPadMedian = 1800;
inline constexpr double kRecordPadSigma = 0.5;
// Every frame sent while idle, and a mail wait's request, fits under the floor.
inline constexpr double kRecordPadFloor = 1536;
inline constexpr double kRecordPadCeiling = 4096;
inline constexpr double kBulkPadMedian = 256;
inline constexpr double kBulkPadSigma = 1.0;
inline constexpr std::size_t kBulkPadMax = 4096;
inline constexpr std::size_t kMaxPaddedBytes = kRecordHeaderBytes + kMaxFrameBytes + kBulkPadMax;
inline constexpr std::size_t kMaxRecordBytes = kMaxPaddedBytes + kAeadTagBytes;

// A media socket's slots drift through regimes; each regime draws its own gap range,
// filler share and voice padding.
inline constexpr std::chrono::milliseconds kMediaRegimeLeast{2000};
inline constexpr std::chrono::milliseconds kMediaRegimeMost{10000};
inline constexpr std::chrono::microseconds kMediaGapFloorLeast{2000};
inline constexpr std::chrono::microseconds kMediaGapFloorMost{10000};
inline constexpr std::chrono::microseconds kMediaGapWidthLeast{22000};
// Bounds the wait of a voice frame at one end.
inline constexpr std::chrono::microseconds kMediaGapCeiling{36000};
inline constexpr double kMediaFillerShareMost = 0.8;
inline constexpr std::size_t kMediaFramesPerRecord = 2;
// Per voice frame, above the longest with its host elided: 2 + 5 + 2 + 28 + a 150-byte Opus frame.
inline constexpr std::size_t kMediaPadPerFrame = 192;
inline constexpr std::size_t kMediaPadSpanLeast = 16;
inline constexpr std::size_t kMediaPadSpanMost = 64;
inline constexpr double kFillerVoiceLike = 0.5;
inline constexpr std::size_t kFillerLeast = 96;
inline constexpr std::size_t kFillerMost = 1200;
inline constexpr std::size_t kMediaQueueLimit = 8;
// A filler waits while this many of the largest fillers have not left yet.
inline constexpr std::size_t kMediaBacklogRecords = 2;
inline constexpr std::size_t kMediaBacklogBytes
    = kMediaBacklogRecords * (kFillerMost + kAeadTagBytes);

class WrongGateway : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

Bytes issueCard(const Identity& identity, const Key& sealing);
Key cardSealingKey(const Bytes& card, const std::string& fingerprint);

// Sealed under a key only a holder of the link has.
class Cover : public KeyedSeal {
public:
    explicit Cover(const std::string& fingerprint);
};

Bytes padded(const Bytes& body);
Bytes unpadded(const Bytes& message);

shape::LogNormal recordPad();
shape::LogNormal bulkPad();

// A record's plaintext: flags, the frame's length, the frame, zeros to the drawn length.
Bytes padRecord(const Bytes& frame, std::uint8_t flags, shape::RandomSource& random);
// A record may carry several frames, each after its length; a record with none is a filler.
struct RecordBody {
    std::uint8_t flags = 0;
    Bytes frame;
    std::vector<Bytes> following;
};
std::optional<RecordBody> unpadRecord(const Bytes& plaintext);
bool isFiller(const RecordBody& body);

struct MediaRegime {
    std::chrono::microseconds gapLeast{0};
    std::chrono::microseconds gapMost{0};
    double fillerShare = 0;
    std::size_t padSpan = 0;
};

MediaRegime drawMediaRegime(shape::RandomSource& random);
std::chrono::microseconds drawMediaGap(const MediaRegime& regime, shape::RandomSource& random);
// From kMediaPadPerFrame per frame to padSpan above it; frames that do not fit there are padded as any record.
Bytes mediaRecord(const std::vector<Bytes>& frames, std::uint8_t flags, const MediaRegime& regime,
    shape::RandomSource& random);
Bytes fillerRecord(std::uint8_t flags, const MediaRegime& regime, shape::RandomSource& random);

// The slots of a media socket are drawn ahead and never moved by what is queued.
class MediaPacer {
public:
    using Clock = std::chrono::steady_clock;

    struct Queued {
        Bytes frame;
        Clock::time_point at;
    };

    struct Slot {
        std::vector<Queued> frames;
        bool filler = false;
    };

    MediaPacer(shape::RandomSource& random, Clock::time_point start);

    // False when the queue was full and its oldest frame was dropped.
    bool queue(Bytes frame, Clock::time_point at);
    Clock::time_point due() const { return due_; }
    // Up to kMediaFramesPerRecord of the oldest frames; with none, a filler at the regime's share.
    Slot take(Clock::time_point now);
    const MediaRegime& regime() const { return regime_; }
    std::size_t queued() const { return frames_.size(); }
    std::uint64_t dropped() const { return dropped_; }

private:
    void enter(Clock::time_point now);

    shape::RandomSource& random_;
    MediaRegime regime_;
    Clock::time_point regimeUntil_;
    Clock::time_point due_;
    std::deque<Queued> frames_;
    std::uint64_t dropped_ = 0;
};

// A raw-send to the host of the raw-send before it on one socket goes with an empty host.
class HostElision {
public:
    Bytes elide(const Bytes& frame);
    // Nothing when a frame names no host and none came before it.
    std::optional<Bytes> restore(const Bytes& frame);

private:
    std::string last_;
};

// Uniform in [kIdleKeepaliveMin, kIdleKeepaliveMax].
std::chrono::milliseconds drawIdleKeepalive(shape::RandomSource& random);

// A keepalive ping carries the same flags a record does.
std::string pingCarrying(std::uint8_t flags);
std::optional<std::uint8_t> flagsOfPing(const std::string& payload);

struct Welcome {
    SecretBytes sessionKey;
    Bytes salt;
    std::vector<Bytes> tickets;
};

struct Hello {
    Key ephemeral;
    Bytes message;
};

Hello makeHello(const Cover& cover, const Key& gatewaySealing);
std::optional<Key> openHello(const Cover& cover, const Bytes& message, const Key& gatewaySealing);

Bytes makeWelcome(const Cover& cover, const Welcome& welcome, const Key& clientEphemeral,
    const Identity& gateway);
std::optional<Welcome> openWelcome(const Cover& cover, const Bytes& message,
    const Key& ephemeral, const std::string& fingerprint);

enum class Side { eClient, eGateway };

// A key and a counter per direction; the counter is the nonce.
class Records {
public:
    Records(const SecretBytes& sessionKey, const Bytes& salt, Side side);

    Bytes seal(const Bytes& plaintext);
    std::optional<Bytes> open(const Bytes& record);

private:
    std::mutex mutex_;
    SecretBytes sendKey_;
    SecretBytes receiveKey_;
    std::uint64_t sent_ = 0;
    std::uint64_t received_ = 0;
};

Bytes makeJoin(const Bytes& ticket, Records& records);
Bytes ticketOf(const Bytes& join);
Bytes joinRecordOf(const Bytes& join);
Bytes makeJoined(Records& records);
bool isJoined(const Bytes& opened);
// As long as a join's answer, and noise.
Bytes refusedJoin();

struct ChannelHooks {
    std::function<std::uint8_t()> flags;
    std::function<void()> sent;
};

class ChannelSocket : public http::Socket {
public:
    ChannelSocket(http::SocketPtr raw, std::shared_ptr<Records> records, ChannelHooks hooks = {});
    ~ChannelSocket() override;
    ChannelSocket(const ChannelSocket&) = delete;
    ChannelSocket& operator=(const ChannelSocket&) = delete;

    void send(std::vector<unsigned char> message) override;
    std::size_t pending() const override;
    void close() override;
    bool open() const override;

    const http::SocketPtr& raw() const { return raw_; }
    std::optional<RecordBody> openRecord(const Bytes& record);
    // Datagrams then leave only in the slots of a MediaPacer.
    void carryMedia();
    std::uint64_t mediaDropped() const;

private:
    void sendSealed(const Bytes& plaintext);
    void pace();
    void stopPacing();

    http::SocketPtr raw_;
    std::shared_ptr<Records> records_;
    ChannelHooks hooks_;
    shape::SystemRandom random_;
    std::mutex sending_;
    mutable std::mutex pacing_;
    std::condition_variable paced_;
    std::optional<MediaPacer> pacer_;
    bool stopping_ = false;
    HostElision sentHosts_;
    std::mutex opening_;
    HostElision heardHosts_;
    std::thread pacerThread_;
};

struct ChannelJoin {
    SecretBytes sessionKey;
    Bytes ticket;
};

struct ChannelOpened {
    std::shared_ptr<ChannelSocket> socket;
    std::optional<Welcome> welcome;
    std::string error;
    bool wrongGateway = false;
    // Spent whatever came back.
    bool ticketSpent = false;
};

using ChannelMessageFn = std::function<void(const http::SocketPtr&, const std::vector<unsigned char>&)>;
using ChannelClosedFn = std::function<void(const http::SocketPtr&)>;

// `welcome` is set only for a new session.
ChannelOpened openChannel(const http::SocketDial& dial, const std::string& fingerprint,
    const std::optional<ChannelJoin>& join, ChannelMessageFn onMessage, ChannelClosedFn onClosed,
    ChannelHooks hooks = {});

}  // namespace bazarish::gateway
