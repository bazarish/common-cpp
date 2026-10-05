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

namespace bazarish::gateway {

inline constexpr int kProtocolVersion = 1;
inline constexpr const char* kSubprotocol = "bazarish-gateway/1";
inline constexpr const char* kTokenHeader = "x-bazarish-gateway";
inline constexpr const char* kSessionHeader = "x-bazarish-session";

inline constexpr std::chrono::seconds kSessionTtl{300};
inline constexpr std::size_t kSessionCookieBytes = 32;
inline constexpr std::size_t kMaxFrameBytes = 16384;
inline constexpr std::size_t kStreamWindowBytes = 256 * 1024;
inline constexpr std::chrono::seconds kDialRetryDelay{2};
inline constexpr std::size_t kInboundQueue = 8;
inline constexpr std::size_t kDatagramQueue = 64;
inline constexpr std::chrono::seconds kKeepalive{30};
inline constexpr std::chrono::seconds kPongTimeout{15};
inline constexpr std::chrono::milliseconds kStatusPeriod{250};
inline constexpr std::size_t kMaxSocketsPerSession = 16;

inline constexpr std::chrono::milliseconds kDecoyMinDelay{500};
inline constexpr std::chrono::milliseconds kDecoyMaxDelay{300000};
inline constexpr std::size_t kDecoyMinBytes = 1024;
inline constexpr std::size_t kDecoyMaxBytes = 256 * 1024;
inline constexpr std::size_t kDecoyRequestMinBytes = 256;
inline constexpr std::size_t kDecoyRequestMaxBytes = 2048;
inline constexpr std::chrono::seconds kControlSocketMinLife{1};
inline constexpr std::chrono::seconds kControlSocketMaxLife{300};
inline constexpr std::chrono::seconds kControlGapMax{2};
inline constexpr std::chrono::milliseconds kControlGapMin{200};

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
};

std::string_view frameTypeName(FrameType type);
std::optional<FrameType> frameTypeFromByte(std::uint8_t value);

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

class ProtocolError : public std::runtime_error {
public:
    ProtocolError(Fault fault, const std::string& message);
    Fault fault() const { return fault_; }

private:
    Fault fault_;
};

inline constexpr std::size_t kFrameHeaderBytes = 5;
inline constexpr std::size_t kMaxBodyBytes = kMaxFrameBytes - kFrameHeaderBytes;

struct Frame {
    FrameType type{};
    std::uint32_t ref = 0;
    Bytes body;
};

Bytes encode(FrameType type, std::uint32_t ref, const void* body, std::size_t size);
Bytes encode(FrameType type, std::uint32_t ref, const Bytes& body = {});
Bytes encodeJson(FrameType type, std::uint32_t ref, const nlohmann::json& body);
Frame decode(const void* data, std::size_t size);
nlohmann::json bodyJson(const Frame& frame);

Bytes encodeCredit(std::uint32_t stream, std::uint64_t total);
std::uint64_t decodeCredit(const Frame& frame);

Bytes encodeRawSend(std::uint32_t endpoint, const std::string& host, const void* data,
    std::size_t size);
std::size_t rawPayloadRoom(const std::string& host);
struct RawSend {
    std::string host;
    Bytes payload;
};
RawSend decodeRawSend(const Frame& frame);

class Ids {
public:
    explicit Ids(bool odd);
    std::uint32_t next();

private:
    std::uint32_t next_;
};

}  // namespace bazarish::gateway
