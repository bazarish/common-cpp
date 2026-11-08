// Bazarish project (c) 2026
#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/JsonRead.hpp"

#include <algorithm>
#include <limits>

namespace bazarish::gateway {

namespace {

constexpr std::uint32_t kIdStep = 2;
constexpr std::size_t kCreditBytes = 8;
constexpr std::size_t kHostLengthBytes = 2;

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
        case FrameType::eTickets: return "tickets";
        case FrameType::eEndpointCreate: return "endpoint-create";
        case FrameType::eEndpointStop: return "endpoint-stop";
        case FrameType::eEndpointStatus: return "endpoint-status";
        case FrameType::eEndpointLost: return "endpoint-lost";
        case FrameType::eEndpointRenew: return "endpoint-renew";
        case FrameType::eEndpointDelegate: return "endpoint-delegate";
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
        case FrameType::eTickets:
        case FrameType::eEndpointCreate:
        case FrameType::eEndpointStop:
        case FrameType::eEndpointStatus:
        case FrameType::eEndpointLost:
        case FrameType::eEndpointRenew:
        case FrameType::eEndpointDelegate:
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

Bytes encode(const FrameType type, const std::uint32_t ref, const ByteView body)
{
    if (body.size() > kMaxBodyBytes) {
        throw ProtocolError(Fault::eBadFrame, "frame body over the cap");
    }
    Bytes out;
    out.reserve(kFrameHeaderBytes + body.size());
    out.push_back(static_cast<unsigned char>(type));
    appendBigEndian(out, ref, sizeof(std::uint32_t));
    if (!body.empty()) {
        out.insert(out.end(), body.begin(), body.end());
    }
    return out;
}

Bytes encodeJson(const FrameType type, const std::uint32_t ref, const nlohmann::json& body)
{
    const std::string text = body.dump();
    return encode(type, ref, viewOf(text));
}

Frame decode(const ByteView data)
{
    if (data.size() < kFrameHeaderBytes) {
        throw ProtocolError(Fault::eBadFrame, "frame shorter than its header");
    }
    if (data.size() > kMaxFrameBytes) {
        throw ProtocolError(Fault::eBadFrame, "frame over the cap");
    }
    const std::optional<FrameType> type = frameTypeFromByte(data[0]);
    if (!type.has_value()) {
        throw ProtocolError(Fault::eBadFrame, "frame type does not exist");
    }
    Frame frame;
    frame.type = type.value();
    frame.ref = static_cast<std::uint32_t>(getBigEndian(data.subspan(1, sizeof(std::uint32_t))));
    const ByteView body = data.subspan(kFrameHeaderBytes);
    frame.body.assign(body.begin(), body.end());
    return frame;
}

nlohmann::json bodyJson(const Frame& frame)
{
    if (!carriesJson(frame.type)) {
        throw ProtocolError(Fault::eBadFrame, "this frame does not carry a document");
    }
    const nlohmann::json body
        = parseJsonOrDiscarded(frame.body);
    if (body.is_discarded() || !body.is_object()) {
        throw ProtocolError(Fault::eBadFrame, "frame body is not a document");
    }
    return body;
}

Bytes encodeCredit(const std::uint32_t stream, const std::uint64_t total)
{
    Bytes body;
    body.reserve(kCreditBytes);
    appendBigEndian(body, total, sizeof(std::uint64_t));
    return encode(FrameType::eStreamCredit, stream, body);
}

std::uint64_t decodeCredit(const Frame& frame)
{
    if (frame.type != FrameType::eStreamCredit || frame.body.size() != kCreditBytes) {
        throw ProtocolError(Fault::eBadFrame, "a credit is one count and nothing else");
    }
    return getBigEndian(frame.body);
}

Bytes encodeRawSend(const std::uint32_t endpoint, const std::string& host, const ByteView data)
{
    if (host.empty() || host.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw ProtocolError(Fault::eBadFrame, "a datagram names one destination");
    }
    const std::uint16_t length = static_cast<std::uint16_t>(host.size());
    Bytes body(kHostLengthBytes + host.size() + data.size());
    putBigEndian(ByteBuffer(body).first(kHostLengthBytes), length);
    const auto hostAt = body.begin() + kHostLengthBytes;
    std::copy(data.begin(), data.end(), std::copy(host.begin(), host.end(), hostAt));
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
    const std::size_t length = getBigEndian(ByteView(frame.body).first(kHostLengthBytes));
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

Ids::Ids(const bool odd)
    : next_(odd ? 1 : kIdStep)
{
}

std::uint32_t Ids::next()
{
    std::uint32_t id = next_.load();
    std::uint32_t following = 0;
    do {
        if (id == 0) {
            throw ProtocolError(Fault::eInternal, "identifier space exhausted");
        }
        following = (id > std::numeric_limits<std::uint32_t>::max() - kIdStep) ? 0 : id + kIdStep;
    } while (!next_.compare_exchange_weak(id, following));
    return id;
}

}  // namespace bazarish::gateway
