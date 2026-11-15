// Bazarish project (c) 2026
#include "bazarish/Tunnel.hpp"
#include "bazarish/JsonRead.hpp"

#include "bazarish/Padding.hpp"

#include "bazarish/Hybrid.hpp"
#include "bazarish/SecretBytes.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace bazarish::tunnel {

namespace {

const char* const kVersionField = "v";
const char* const kTypeField = "t";
const char* const kSealedField = "s";
const char* const kHandleField = "h";
const char* const kNonceField = "n";
const char* const kCipherField = "c";

const char* const kHelloType = "h";
const char* const kCarryType = "c";

// RFC 8949: an item's head is at most 9 bytes; the slack covers the map and its six keys.
constexpr std::size_t kCborHeadBytes = 9;
constexpr std::size_t kCborSlackBytes = 128;

const char* const kRequestKeyInfo = "bazarish tunnel request v1";
const char* const kAnswerKeyInfo = "bazarish tunnel answer v1";

Bytes toCbor(const nlohmann::json& value)
{
    return nlohmann::json::to_cbor(value);
}

nlohmann::json fromCbor(const Bytes& bytes)
{
    return parseCbor(bytes);
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

nlohmann::json frameOf(const Bytes& frame)
{
    const nlohmann::json parsed = fromCbor(frame);
    if (parsed.value(kVersionField, 0) != kFrameVersion) {
        throw std::runtime_error("tunnel frame is of another version");
    }
    return parsed;
}

SecretBytes frameKey(const SecretBytes& tunnelKey, const Direction direction, const std::string& handle)
{
    return SecretBytes(hkdfSha256(tunnelKey.bytes(), Bytes(handle.begin(), handle.end()),
        direction == Direction::eRequest ? kRequestKeyInfo : kAnswerKeyInfo, kAeadKeyBytes));
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

SecretBytes deriveTunnelKey(const SecretBytes& secret, const std::string& sessionId)
{
    return SecretBytes(sha256(secretHexLine(secret, "|" + sessionId + "|bazarish tunnel v1").bytes()));
}

SecretBytes helloSigned(const SecretBytes& secret, const std::string& serverFingerprint)
{
    if (serverFingerprint.empty()) {
        throw std::invalid_argument("a hello names the server it is for");
    }
    const SecretJson signedPart(
        nlohmann::json{{"secret", asBinary(secret.bytes())}, {"server", serverFingerprint}});
    return SecretBytes(toCbor(signedPart.value));
}

Bytes sealHello(const Hello& hello, const Key& serverSealingPublic)
{
    const SecretJson inner(nlohmann::json{
        {"secret", asBinary(hello.secret.bytes())},
        {"replyKey", asBinary(hello.replyKeyDer)},
        {"sig", headersToJson(hello.signature)},
    });
    const SecretBytes encoded(toCbor(inner.value));
    const nlohmann::json frame = {
        {kVersionField, kFrameVersion},
        {kTypeField, kHelloType},
        {kSealedField, asBinary(hybrid::seal(padToLadder(encoded).bytes(), serverSealingPublic, {}))},
    };
    return toCbor(frame);
}

Hello openHello(const Bytes& frame, const Key& serverSealingPrivate)
{
    const nlohmann::json parsed = frameOf(frame);
    if (parsed.value(kTypeField, std::string()) != kHelloType) {
        throw std::runtime_error("tunnel frame does not open a tunnel");
    }
    const SecretBytes padded = hybrid::unseal(fromBinary(parsed.at(kSealedField)), serverSealingPrivate);
    const SecretJson inner(fromCbor(unpadFromLadder(padded).bytes()));
    Hello hello;
    hello.secret = SecretBytes(fromBinary(inner.value.at("secret")));
    hello.replyKeyDer = fromBinary(inner.value.at("replyKey"));
    hello.signature = headersFromJson(inner.value.at("sig"));
    return hello;
}

Bytes sealWelcome(const Welcome& welcome, const Key& replyKeyPublic)
{
    const nlohmann::json inner = {{"expiresUnix", welcome.expiresUnix}};
    return hybrid::seal(padToLadder(toCbor(inner)), replyKeyPublic, {});
}

Welcome openWelcome(const Bytes& sealed, const Key& replyKeyPrivate)
{
    const nlohmann::json inner = fromCbor(unpadFromLadder(hybrid::unseal(sealed, replyKeyPrivate)).bytes());
    Welcome welcome;
    welcome.expiresUnix = inner.at("expiresUnix").get<std::int64_t>();
    return welcome;
}

Bytes carry(const std::string& handle, const SecretBytes& tunnelKey, const Direction direction,
    const SecretBytes& plaintext)
{
    const Bytes nonce = randomBytes(kAeadNonceBytes);
    const nlohmann::json frame = {
        {kVersionField, kFrameVersion},
        {kTypeField, kCarryType},
        {kHandleField, handle},
        {kNonceField, asBinary(nonce)},
        {kCipherField, asBinary(aeadSeal(frameKey(tunnelKey, direction, handle).bytes(), nonce, padToLadder(plaintext).bytes()))},
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

SecretBytes open(
    const Bytes& frame, const SecretBytes& tunnelKey, const Direction direction, const std::string& handle)
{
    const nlohmann::json parsed = frameOf(frame);
    if (parsed.value(kTypeField, std::string()) != kCarryType) {
        throw std::runtime_error("tunnel frame carries nothing");
    }
    if (parsed.at(kHandleField).get<std::string>() != handle) {
        throw std::runtime_error("tunnel frame names another handle");
    }
    const std::optional<SecretBytes> opened = aeadOpen(frameKey(tunnelKey, direction, handle).bytes(),
        fromBinary(parsed.at(kNonceField)), fromBinary(parsed.at(kCipherField)));
    if (!opened.has_value()) {
        throw std::runtime_error("tunnel frame did not open");
    }
    return unpadFromLadder(*opened);
}

SecretBytes encodeRequest(const Request& request)
{
    SecretJson inner(nlohmann::json{
        {"m", request.method},
        {"p", request.path},
        {"q", request.query},
        {"h", headersToJson(request.headers)},
        {"c", request.contentType},
    });
    inner.value["b"] = nlohmann::json::binary(Bytes(request.body.bytes()));
    std::size_t bound = kCborSlackBytes + request.body.size() + request.method.size()
        + request.path.size() + request.query.size() + request.contentType.size();
    for (const auto& [name, value] : request.headers) {
        bound += name.size() + value.size() + 2 * kCborHeadBytes;
    }
    Bytes encoded;
    encoded.reserve(bound);
    const unsigned char* const reserved = encoded.data();
    nlohmann::json::to_cbor(inner.value, encoded);
    if (encoded.data() != reserved) {
        throw std::logic_error("a tunnel request outgrew its buffer and left a copy behind");
    }
    return SecretBytes(std::move(encoded));
}

Request decodeRequest(const SecretBytes& plaintext)
{
    const SecretJson inner(fromCbor(plaintext.bytes()));
    Request request;
    request.method = inner.value.at("m").get<std::string>();
    request.path = inner.value.at("p").get<std::string>();
    request.query = inner.value.value("q", std::string());
    request.headers = headersFromJson(inner.value.at("h"));
    request.body = SecretBytes(fromBinary(inner.value.at("b")));
    request.contentType = inner.value.value("c", std::string());
    return request;
}

SecretBytes encodeResponse(const Response& response)
{
    const SecretJson inner(nlohmann::json{
        {"s", response.status},
        {"c", response.contentType},
        {"b", asBinary(response.body)},
    });
    return SecretBytes(toCbor(inner.value));
}

Response decodeResponse(const SecretBytes& plaintext)
{
    const SecretJson inner(fromCbor(plaintext.bytes()));
    Response response;
    response.status = inner.value.at("s").get<int>();
    response.contentType = inner.value.value("c", std::string());
    response.body = fromBinary(inner.value.at("b"));
    return response;
}

}  // namespace bazarish::tunnel
