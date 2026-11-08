// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/KeyedSeal.hpp"
#include "bazarish/WebSocket.hpp"
#include "bazarish/WebSocketClient.hpp"

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
inline constexpr std::size_t kMaxRecordBytes = kMaxFrameBytes + kAeadTagBytes;

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

class ChannelSocket : public http::Socket {
public:
    ChannelSocket(http::SocketPtr raw, std::shared_ptr<Records> records);

    void send(std::vector<unsigned char> message) override;
    std::size_t pending() const override;
    void close() override;
    bool open() const override;

    const http::SocketPtr& raw() const { return raw_; }
    std::optional<Bytes> openRecord(const Bytes& record);

private:
    http::SocketPtr raw_;
    std::shared_ptr<Records> records_;
    std::mutex sending_;
};

struct ChannelJoin {
    Bytes sessionKey;
    Bytes ticket;
};

struct ChannelOpened {
    http::SocketPtr socket;
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
    const std::optional<ChannelJoin>& join, ChannelMessageFn onMessage, ChannelClosedFn onClosed);

}  // namespace bazarish::gateway
