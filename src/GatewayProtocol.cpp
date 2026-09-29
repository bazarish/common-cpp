// Bazarish project (c) 2026
#include "bazarish/GatewayProtocol.hpp"

#include <cstring>
#include <limits>

namespace bazarish::gateway {

namespace {

constexpr int kBitsPerByte = 8;
constexpr std::uint32_t kByteMask = 0xFF;
// The client takes even identifiers and the gateway odd ones, so each side
// allocates without asking.
constexpr std::uint32_t kIdStep = 2;
// A credit is one cumulative count; a datagram names its destination with a
// length that fits any I2P host.
constexpr std::size_t kCreditBytes = 8;
constexpr std::size_t kHostLengthBytes = 2;

void appendBigEndian32(Bytes& out, const std::uint32_t value)
{
    out.push_back(static_cast<unsigned char>((value >> (3 * kBitsPerByte)) & kByteMask));
    out.push_back(static_cast<unsigned char>((value >> (2 * kBitsPerByte)) & kByteMask));
    out.push_back(static_cast<unsigned char>((value >> kBitsPerByte) & kByteMask));
    out.push_back(static_cast<unsigned char>(value & kByteMask));
}

void appendBigEndian64(Bytes& out, const std::uint64_t value)
{
    for (int shift = 7; shift >= 0; --shift) {
        out.push_back(static_cast<unsigned char>((value >> (shift * kBitsPerByte)) & kByteMask));
    }
}

std::uint64_t readBigEndian64(const unsigned char* const at)
{
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
        value = (value << kBitsPerByte) | static_cast<std::uint64_t>(at[i]);
    }
    return value;
}

std::uint32_t readBigEndian32(const unsigned char* const at)
{
    return (static_cast<std::uint32_t>(at[0]) << (3 * kBitsPerByte))
        | (static_cast<std::uint32_t>(at[1]) << (2 * kBitsPerByte))
        | (static_cast<std::uint32_t>(at[2]) << kBitsPerByte)
        | static_cast<std::uint32_t>(at[3]);
}

std::uint16_t readBigEndian16(const unsigned char* const at)
{
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(at[0]) << kBitsPerByte) | static_cast<std::uint16_t>(at[1]));
}

// A frame whose body is a document. The rest carry bytes, because base64
// over a 16 KiB chunk of a file would be a third of the connection spent
// on nothing.
bool carriesJson(const FrameType type)
{
    switch (type) {
        case FrameType::eStreamData:
        case FrameType::eStreamCredit:
        case FrameType::eStreamClose:
        case FrameType::eRawSend:
        case FrameType::eRawRecv:
            return false;
        default:
            return true;
    }
}

}  // namespace

ProtocolError::ProtocolError(const Fault fault, const std::string& message)
    : std::runtime_error(message)
    , fault_(fault)
{
}

std::string_view frameTypeName(const FrameType type)
{
    switch (type) {
        case FrameType::eHello: return "hello";
        case FrameType::eReady: return "ready";
        case FrameType::eOk: return "ok";
        case FrameType::eError: return "error";
        case FrameType::eResume: return "resume";
        case FrameType::eAttach: return "attach";
        case FrameType::eEndpointCreate: return "endpoint-create";
        case FrameType::eEndpointStop: return "endpoint-stop";
        case FrameType::eEndpointStatus: return "endpoint-status";
        case FrameType::eStreamOpen: return "stream-open";
        case FrameType::eStreamOpened: return "stream-opened";
        case FrameType::eStreamInbound: return "stream-inbound";
        case FrameType::eStreamData: return "stream-data";
        case FrameType::eStreamCredit: return "stream-credit";
        case FrameType::eStreamClose: return "stream-close";
        case FrameType::eStreamReset: return "stream-reset";
        case FrameType::eRawSend: return "raw-send";
        case FrameType::eRawRecv: return "raw-recv";
    }
    return "unknown";
}

std::optional<FrameType> frameTypeFromByte(const std::uint8_t value)
{
    switch (static_cast<FrameType>(value)) {
        case FrameType::eHello:
        case FrameType::eReady:
        case FrameType::eOk:
        case FrameType::eError:
        case FrameType::eResume:
        case FrameType::eAttach:
        case FrameType::eEndpointCreate:
        case FrameType::eEndpointStop:
        case FrameType::eEndpointStatus:
        case FrameType::eStreamOpen:
        case FrameType::eStreamOpened:
        case FrameType::eStreamInbound:
        case FrameType::eStreamData:
        case FrameType::eStreamCredit:
        case FrameType::eStreamClose:
        case FrameType::eStreamReset:
        case FrameType::eRawSend:
        case FrameType::eRawRecv:
            return static_cast<FrameType>(value);
    }
    return std::nullopt;
}

std::string_view faultName(const Fault fault)
{
    switch (fault) {
        case Fault::eVersion: return "version";
        case Fault::eBadFrame: return "bad-frame";
        case Fault::eUnknownId: return "unknown-id";
        case Fault::eNoEndpoint: return "no-endpoint";
        case Fault::eUnsupported: return "unsupported";
        case Fault::eRefused: return "refused";
        case Fault::eUnreachable: return "unreachable";
        case Fault::eTimeout: return "timeout";
        case Fault::eClosed: return "closed";
        case Fault::eWrongLane: return "wrong-lane";
        case Fault::eInternal: return "internal";
    }
    return "internal";
}

Bytes encode(const FrameType type, const std::uint32_t ref, const void* const body,
    const std::size_t size)
{
    if (size > kMaxBodyBytes) {
        throw ProtocolError(Fault::eBadFrame, "frame body over the cap");
    }
    Bytes out;
    out.reserve(kFrameHeaderBytes + size);
    out.push_back(static_cast<unsigned char>(type));
    appendBigEndian32(out, ref);
    if (size > 0) {
        const unsigned char* const at = static_cast<const unsigned char*>(body);
        out.insert(out.end(), at, at + size);
    }
    return out;
}

Bytes encode(const FrameType type, const std::uint32_t ref, const Bytes& body)
{
    return encode(type, ref, body.data(), body.size());
}

Bytes encodeJson(const FrameType type, const std::uint32_t ref, const nlohmann::json& body)
{
    const std::string text = body.dump();
    return encode(type, ref, text.data(), text.size());
}

Frame decode(const void* const data, const std::size_t size)
{
    if (size < kFrameHeaderBytes) {
        throw ProtocolError(Fault::eBadFrame, "frame shorter than its header");
    }
    if (size > kMaxFrameBytes) {
        throw ProtocolError(Fault::eBadFrame, "frame over the cap");
    }
    const unsigned char* const at = static_cast<const unsigned char*>(data);
    const std::optional<FrameType> type = frameTypeFromByte(at[0]);
    if (!type.has_value()) {
        throw ProtocolError(Fault::eBadFrame, "frame type does not exist");
    }
    Frame frame;
    frame.type = type.value();
    frame.ref = readBigEndian32(at + 1);
    frame.body.assign(at + kFrameHeaderBytes, at + size);
    return frame;
}

nlohmann::json bodyJson(const Frame& frame)
{
    if (!carriesJson(frame.type)) {
        throw ProtocolError(Fault::eBadFrame, "this frame does not carry a document");
    }
    const nlohmann::json body
        = nlohmann::json::parse(frame.body.begin(), frame.body.end(), nullptr, false);
    if (body.is_discarded() || !body.is_object()) {
        throw ProtocolError(Fault::eBadFrame, "frame body is not a document");
    }
    return body;
}

Bytes encodeCredit(const std::uint32_t stream, const std::uint64_t total)
{
    Bytes body;
    body.reserve(kCreditBytes);
    appendBigEndian64(body, total);
    return encode(FrameType::eStreamCredit, stream, body);
}

std::uint64_t decodeCredit(const Frame& frame)
{
    if (frame.type != FrameType::eStreamCredit || frame.body.size() != kCreditBytes) {
        throw ProtocolError(Fault::eBadFrame, "a credit is one count and nothing else");
    }
    return readBigEndian64(frame.body.data());
}

Bytes encodeRawSend(const std::uint32_t endpoint, const std::string& host, const void* const data,
    const std::size_t size)
{
    if (host.empty() || host.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw ProtocolError(Fault::eBadFrame, "a datagram names one destination");
    }
    const std::uint16_t length = static_cast<std::uint16_t>(host.size());
    Bytes body(kHostLengthBytes + host.size() + size);
    body[0] = static_cast<unsigned char>((length >> kBitsPerByte) & kByteMask);
    body[1] = static_cast<unsigned char>(length & kByteMask);
    std::memcpy(body.data() + kHostLengthBytes, host.data(), host.size());
    if (size > 0) {
        std::memcpy(body.data() + kHostLengthBytes + host.size(), data, size);
    }
    return encode(FrameType::eRawSend, endpoint, body);
}

std::size_t rawPayloadRoom(const std::string& host)
{
    const std::size_t taken = kHostLengthBytes + host.size();
    return taken < kMaxBodyBytes ? kMaxBodyBytes - taken : 0;
}

RawSend decodeRawSend(const Frame& frame)
{
    if (frame.type != FrameType::eRawSend || frame.body.size() < kHostLengthBytes) {
        throw ProtocolError(Fault::eBadFrame, "not a datagram going out");
    }
    const std::size_t length = readBigEndian16(frame.body.data());
    if (length == 0 || frame.body.size() < kHostLengthBytes + length) {
        throw ProtocolError(Fault::eBadFrame, "a datagram names one destination");
    }
    RawSend out;
    out.host.assign(frame.body.begin() + kHostLengthBytes,
        frame.body.begin() + kHostLengthBytes + static_cast<std::ptrdiff_t>(length));
    out.payload.assign(
        frame.body.begin() + kHostLengthBytes + static_cast<std::ptrdiff_t>(length),
        frame.body.end());
    return out;
}

// Zero is not an identifier: it is what a frame with no subject of its own
// carries, and keeping it out of the space is what lets that stay unambiguous.
Ids::Ids(const bool odd)
    : next_(odd ? 1 : kIdStep)
{
}

std::uint32_t Ids::next()
{
    if (next_ == 0) {
        throw ProtocolError(Fault::eInternal, "identifier space exhausted");
    }
    const std::uint32_t id = next_;
    next_ = (id > std::numeric_limits<std::uint32_t>::max() - kIdStep) ? 0 : id + kIdStep;
    return id;
}

}  // namespace bazarish::gateway
