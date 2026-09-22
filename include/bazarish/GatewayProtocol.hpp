// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

// The wire between a client whose own I2P router is switched off and the
// gateway that runs one for it. This header is the whole of the protocol: both
// sides encode and decode through it, so a change to the wire is a change in
// one place.
namespace bazarish::gateway {

inline constexpr int kProtocolVersion = 1;
inline constexpr const char* kSubprotocol = "bazarish-gateway/1";
// Header keys arrive lowercased from the HTTP engine.
inline constexpr const char* kTokenHeader = "x-bazarish-gateway";
inline constexpr const char* kSessionHeader = "x-bazarish-session";

// How long a session outlives its last socket. Long enough for a lift, a tunnel
// or a handover; short enough that an abandoned phone costs the gateway five
// minutes of tunnels.
inline constexpr std::chrono::seconds kSessionTtl{300};
inline constexpr std::size_t kSessionCookieBytes = 32;
// A WebSocket message cannot be interleaved with another, so this is the
// longest anything can be held by one already going out.
inline constexpr std::size_t kMaxFrameBytes = 16384;
// The in-flight allowance per stream per direction. It is also the retained
// buffer a reconnect replays from, and the most an unaccepted inbound stream
// can cost the gateway.
inline constexpr std::size_t kStreamWindowBytes = 256 * 1024;
// A dial is re-issued this often while the caller's deadline holds: a LeaseSet
// that is not in the netDb yet is a reason to try again, not to fail.
inline constexpr std::chrono::seconds kDialRetryDelay{2};
inline constexpr std::size_t kInboundQueue = 8;
inline constexpr std::size_t kDatagramQueue = 64;
inline constexpr std::chrono::seconds kKeepalive{30};
inline constexpr std::chrono::seconds kPongTimeout{15};
inline constexpr std::chrono::seconds kStatusPeriod{2};
inline constexpr std::size_t kMaxSocketsPerSession = 16;

// Cover traffic. The answer's length is drawn by the gateway and the request's
// by the client, so neither side's behaviour alone decides what the host's
// traffic looks like.
inline constexpr std::chrono::milliseconds kDecoyMinDelay{500};
inline constexpr std::chrono::milliseconds kDecoyMaxDelay{300000};
inline constexpr std::size_t kDecoyMinBytes = 1024;
inline constexpr std::size_t kDecoyMaxBytes = 256 * 1024;
inline constexpr std::size_t kDecoyRequestMinBytes = 256;
inline constexpr std::size_t kDecoyRequestMaxBytes = 2048;
// The control socket is replaced on purpose, so that a watcher sees a host
// being fetched from rather than one connection that lives for hours.
inline constexpr std::chrono::seconds kControlSocketMinLife{1};
inline constexpr std::chrono::seconds kControlSocketMaxLife{300};
inline constexpr std::chrono::seconds kControlGapMax{30};

enum class FrameType : std::uint8_t {
    eHello = 0x01,
    eReady = 0x02,
    eOk = 0x03,
    eError = 0x04,
    eResume = 0x05,
    eAttach = 0x06,
    eEndpointCreate = 0x10,
    eEndpointStop = 0x11,
    eEndpointStatus = 0x12,
    eStreamOpen = 0x20,
    eStreamOpened = 0x21,
    eStreamInbound = 0x22,
    eStreamData = 0x23,
    eStreamCredit = 0x24,
    eStreamClose = 0x25,
    eStreamReset = 0x26,
    eRawSend = 0x30,
    eRawRecv = 0x31,
    eRouterStatus = 0x40,
};

std::string_view frameTypeName(FrameType type);
std::optional<FrameType> frameTypeFromByte(std::uint8_t value);
// True for the frames whose body is JSON. The rest carry bytes, because base64
// over a 16 KiB chunk of a file would be a third of the connection spent on
// nothing.
bool carriesJson(FrameType type);
// True for the frames that ride a flow's own socket when it has one.
bool ridesFlowSocket(FrameType type);

// What one side tells the other went wrong. An operation the gateway cannot
// perform is one of these; it is never a zero, an empty list or a quiet success.
enum class Fault {
    eVersion,
    eBadFrame,
    eUnknownId,
    eNoEndpoint,
    eUnsupported,
    eRefused,
    eUnreachable,
    eTimeout,
    eClosed,
    eWrongLane,
    eInternal,
};

std::string_view faultName(Fault fault);
std::optional<Fault> faultFromName(std::string_view name);

class ProtocolError : public std::runtime_error {
public:
    ProtocolError(Fault fault, const std::string& message);
    Fault fault() const { return fault_; }

private:
    Fault fault_;
};

// type + ref. A body of bytes follows, and a WebSocket message delimits the
// whole of it, so no length rides on the wire.
inline constexpr std::size_t kFrameHeaderBytes = 5;
inline constexpr std::size_t kMaxBodyBytes = kMaxFrameBytes - kFrameHeaderBytes;

struct Frame {
    FrameType type{};
    // A request id, an endpoint id or a stream id, depending on the type. One
    // space for all three, so a response can echo it without ambiguity.
    std::uint32_t ref = 0;
    Bytes body;
};

Bytes encode(FrameType type, std::uint32_t ref, const void* body, std::size_t size);
Bytes encode(FrameType type, std::uint32_t ref, const Bytes& body = {});
Bytes encodeJson(FrameType type, std::uint32_t ref, const nlohmann::json& body);
// Throws ProtocolError for a message that is too short, too long, or names a
// type that does not exist: a gateway that ignores what it does not understand
// is a gateway that silently does half of what was asked.
Frame decode(const void* data, std::size_t size);
nlohmann::json bodyJson(const Frame& frame);

// A credit says how many bytes have left the receiver's hands **in total**. It
// is cumulative on purpose: it is then the same count the resume exchange asks
// for, so flow control and durability are one mechanism rather than two that
// can disagree, and a credit lost with a socket costs nothing because the next
// one says the same thing with more of it. Eight bytes, because a file is not
// promised to stay under four gigabytes.
Bytes encodeCredit(std::uint32_t stream, std::uint64_t total);
std::uint64_t decodeCredit(const Frame& frame);

// A datagram going out names its destination; one coming back does not, because
// a raw datagram carries no sender identity.
Bytes encodeRawSend(std::uint32_t endpoint, const std::string& host, const void* data,
    std::size_t size);
struct RawSend {
    std::string host;
    Bytes payload;
};
RawSend decodeRawSend(const Frame& frame);

// Identifiers are never reused inside a session, which is what lets a `ref`
// serve as an idempotency key for a request that has to be sent again, and what
// makes a frame arriving after its subject is gone recognisably stale. The
// client allocates even values and the gateway odd ones, so the two never
// collide without either asking the other.
class Ids {
public:
    explicit Ids(bool odd);
    // Throws when the space is exhausted: the side that runs out ends the
    // session rather than starting to reuse.
    std::uint32_t next();

private:
    std::uint32_t next_;
};

}  // namespace bazarish::gateway
