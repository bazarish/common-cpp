// Bazarish project (c) 2026
#include "bazarish/Tunnel.hpp"

#include "bazarish/Cms.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace bazarish::tunnel {

namespace {

// Frame fields, kept to one letter each: every byte here is carried on every
// request, and none of them means anything to the facade.
const char* const kVersionField = "v";
const char* const kTypeField = "t";
const char* const kSealedField = "s";
const char* const kHandleField = "h";
const char* const kNonceField = "n";
const char* const kCipherField = "c";

const char* const kHelloType = "h";
const char* const kCarryType = "c";

// The length prefix in front of a padded payload: four bytes, big-endian, so
// the padding that follows is not part of what is decoded.
constexpr std::size_t kLengthPrefixBytes = 4;

Bytes toCbor(const nlohmann::json& value)
{
    return nlohmann::json::to_cbor(value);
}

nlohmann::json fromCbor(const Bytes& bytes)
{
    return nlohmann::json::from_cbor(bytes);
}

nlohmann::json::binary_t asBinary(const Bytes& bytes)
{
    return nlohmann::json::binary_t(std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
}

Bytes fromBinary(const nlohmann::json& value)
{
    const nlohmann::json::binary_t& binary = value.get_binary();
    return Bytes(binary.begin(), binary.end());
}

// The size a payload of this length is padded up to.
std::size_t paddedSize(const std::size_t length)
{
    for (const std::size_t step : kPaddingLadder) {
        if (length <= step) {
            return step;
        }
    }
    const std::size_t largest = kPaddingLadder[std::size(kPaddingLadder) - 1];
    return ((length + largest - 1) / largest) * largest;
}

// Length-prefixed and padded to a step of the ladder, so what the facade
// measures is the step and not the content.
Bytes pad(const Bytes& payload)
{
    const std::size_t total = paddedSize(payload.size() + kLengthPrefixBytes);
    Bytes padded(total, 0);
    const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
    padded[0] = static_cast<std::uint8_t>((length >> 24) & 0xFF);
    padded[1] = static_cast<std::uint8_t>((length >> 16) & 0xFF);
    padded[2] = static_cast<std::uint8_t>((length >> 8) & 0xFF);
    padded[3] = static_cast<std::uint8_t>(length & 0xFF);
    std::copy(payload.begin(), payload.end(), padded.begin() + kLengthPrefixBytes);
    return padded;
}

Bytes unpad(const Bytes& padded)
{
    if (padded.size() < kLengthPrefixBytes) {
        throw std::runtime_error("tunnel payload is too short to carry its own length");
    }
    const std::size_t length = (static_cast<std::size_t>(padded[0]) << 24)
        | (static_cast<std::size_t>(padded[1]) << 16) | (static_cast<std::size_t>(padded[2]) << 8)
        | static_cast<std::size_t>(padded[3]);
    if (length > padded.size() - kLengthPrefixBytes) {
        throw std::runtime_error("tunnel payload claims to be longer than it is");
    }
    return Bytes(padded.begin() + kLengthPrefixBytes,
        padded.begin() + kLengthPrefixBytes + static_cast<std::ptrdiff_t>(length));
}

nlohmann::json frameOf(const Bytes& frame)
{
    const nlohmann::json parsed = fromCbor(frame);
    if (parsed.value(kVersionField, 0) != kFrameVersion) {
        throw std::runtime_error("tunnel frame is of another version");
    }
    return parsed;
}

nlohmann::json headersToJson(const std::map<std::string, std::string>& headers)
{
    nlohmann::json out = nlohmann::json::object();
    for (const auto& [name, value] : headers) {
        out[name] = value;
    }
    return out;
}

std::map<std::string, std::string> headersFromJson(const nlohmann::json& value)
{
    std::map<std::string, std::string> headers;
    for (const auto& [name, held] : value.items()) {
        headers[name] = held.get<std::string>();
    }
    return headers;
}

}  // namespace

Bytes deriveTunnelKey(const Bytes& secret, const std::string& sessionId)
{
    // The same shape as the session MAC key derivation, with its own label: one
    // secret, two keys, and neither is computable from the other.
    const std::string material = toHex(secret) + "|" + sessionId + "|bazarish tunnel v1";
    return sha256(Bytes(material.begin(), material.end()));
}

Bytes sealHello(const Hello& hello, const Key& serverSealingPublic)
{
    nlohmann::json inner = {
        {"secret", asBinary(hello.secret)},
        {"replyKey", asBinary(hello.replyKeyDer)},
        {"sig", headersToJson(hello.signature)},
    };
    const nlohmann::json frame = {
        {kVersionField, kFrameVersion},
        {kTypeField, kHelloType},
        {kSealedField, asBinary(cms::seal(pad(toCbor(inner)), serverSealingPublic))},
    };
    return toCbor(frame);
}

Hello openHello(const Bytes& frame, const Key& serverSealingPrivate)
{
    const nlohmann::json parsed = frameOf(frame);
    if (parsed.value(kTypeField, std::string()) != kHelloType) {
        throw std::runtime_error("tunnel frame does not open a tunnel");
    }
    const nlohmann::json inner
        = fromCbor(unpad(cms::unseal(fromBinary(parsed.at(kSealedField)), serverSealingPrivate)));
    Hello hello;
    hello.secret = fromBinary(inner.at("secret"));
    hello.replyKeyDer = fromBinary(inner.at("replyKey"));
    hello.signature = headersFromJson(inner.at("sig"));
    return hello;
}

Bytes sealWelcome(const Welcome& welcome, const Key& replyKeyPublic)
{
    const nlohmann::json inner = {{"expiresUnix", welcome.expiresUnix}};
    return cms::seal(pad(toCbor(inner)), replyKeyPublic);
}

Welcome openWelcome(const Bytes& sealed, const Key& replyKeyPrivate)
{
    const nlohmann::json inner = fromCbor(unpad(cms::unseal(sealed, replyKeyPrivate)));
    Welcome welcome;
    welcome.expiresUnix = inner.at("expiresUnix").get<std::int64_t>();
    return welcome;
}

Bytes carry(const std::string& handle, const Bytes& tunnelKey, const Bytes& plaintext)
{
    const Bytes nonce = randomBytes(kAeadNonceBytes);
    // Padded here rather than by whoever built the payload: this is the one
    // place that decides what the wire carries, and so the only place that can
    // decide what its length says.
    const nlohmann::json frame = {
        {kVersionField, kFrameVersion},
        {kTypeField, kCarryType},
        {kHandleField, handle},
        {kNonceField, asBinary(nonce)},
        {kCipherField, asBinary(aeadSeal(tunnelKey, nonce, pad(plaintext)))},
    };
    return toCbor(frame);
}

std::string handleOf(const Bytes& frame)
{
    const nlohmann::json parsed = frameOf(frame);
    if (parsed.value(kTypeField, std::string()) != kCarryType) {
        throw std::runtime_error("tunnel frame carries nothing");
    }
    return parsed.at(kHandleField).get<std::string>();
}

bool isHello(const Bytes& frame)
{
    try {
        return frameOf(frame).value(kTypeField, std::string()) == kHelloType;
    } catch (const std::exception&) {
        return false;
    }
}

Bytes open(const Bytes& frame, const Bytes& tunnelKey)
{
    const nlohmann::json parsed = frameOf(frame);
    if (parsed.value(kTypeField, std::string()) != kCarryType) {
        throw std::runtime_error("tunnel frame carries nothing");
    }
    const std::optional<Bytes> opened = aeadOpen(
        tunnelKey, fromBinary(parsed.at(kNonceField)), fromBinary(parsed.at(kCipherField)));
    if (!opened.has_value()) {
        throw std::runtime_error("tunnel frame did not open");
    }
    return unpad(*opened);
}

Bytes encodeRequest(const Request& request)
{
    const nlohmann::json inner = {
        {"m", request.method},
        {"p", request.path},
        {"q", request.query},
        {"h", headersToJson(request.headers)},
        {"b", asBinary(request.body)},
        {"c", request.contentType},
    };
    return toCbor(inner);
}

Request decodeRequest(const Bytes& plaintext)
{
    const nlohmann::json inner = fromCbor(plaintext);
    Request request;
    request.method = inner.at("m").get<std::string>();
    request.path = inner.at("p").get<std::string>();
    request.query = inner.value("q", std::string());
    request.headers = headersFromJson(inner.at("h"));
    request.body = fromBinary(inner.at("b"));
    request.contentType = inner.value("c", std::string());
    return request;
}

Bytes encodeResponse(const Response& response)
{
    const nlohmann::json inner = {
        {"s", response.status},
        {"c", response.contentType},
        {"b", asBinary(response.body)},
    };
    return toCbor(inner);
}

Response decodeResponse(const Bytes& plaintext)
{
    const nlohmann::json inner = fromCbor(plaintext);
    Response response;
    response.status = inner.at("s").get<int>();
    response.contentType = inner.value("c", std::string());
    response.body = fromBinary(inner.at("b"));
    return response;
}

}  // namespace bazarish::tunnel
