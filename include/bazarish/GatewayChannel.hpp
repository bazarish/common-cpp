// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/KeyedSeal.hpp"
#include "bazarish/TrafficShape.hpp"
#include "bazarish/WebSocket.hpp"
#include "bazarish/WebSocketClient.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
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
Bytes bareRecord(const Bytes& frame, std::uint8_t flags);

struct RecordBody {
    std::uint8_t flags = 0;
    Bytes frame;
};
std::optional<RecordBody> unpadRecord(const Bytes& plaintext);

// A keepalive ping carries the same flags a record does.
std::string pingCarrying(std::uint8_t flags);
std::optional<std::uint8_t> flagsOfPing(const std::string& payload);

struct Welcome {
    Bytes sessionKey;
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
    Records(const Bytes& sessionKey, const Bytes& salt, Side side);

    Bytes seal(const Bytes& plaintext);
    std::optional<Bytes> open(const Bytes& record);

private:
    std::mutex mutex_;
    Bytes sendKey_;
    Bytes receiveKey_;
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

    void send(std::vector<unsigned char> message) override;
    std::size_t pending() const override;
    void close() override;
    bool open() const override;

    const http::SocketPtr& raw() const { return raw_; }
    std::optional<RecordBody> openRecord(const Bytes& record);
    void carryMedia() { media_.store(true); }

private:
    http::SocketPtr raw_;
    std::shared_ptr<Records> records_;
    ChannelHooks hooks_;
    shape::SystemRandom random_;
    std::mutex sending_;
    std::atomic<bool> media_{false};
};

struct ChannelJoin {
    Bytes sessionKey;
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
