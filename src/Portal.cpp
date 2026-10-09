// Bazarish project (c) 2026
#include "bazarish/Portal.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>

#include <nlohmann/json.hpp>
#include <openssl/asn1.h>

#include <algorithm>
#include <array>
#include <stdexcept>

namespace bazarish::service {

namespace {

struct CodePointRange {
    unsigned long first;
    unsigned long last;
};

// SignInWithKey.md, "The consumer": C0, DEL, C1, the line and paragraph separators, bidi controls.
constexpr std::array<CodePointRange, 6> kForbiddenCodePoints = {{
    {0x0000, 0x001F},
    {0x007F, 0x009F},
    {0x061C, 0x061C},
    {0x200E, 0x200F},
    {0x2028, 0x202E},
    {0x2066, 0x2069},
}};

bool isForbidden(const unsigned long codePoint)
{
    return std::any_of(kForbiddenCodePoints.begin(), kForbiddenCodePoints.end(),
        [codePoint](const CodePointRange& range) {
            return codePoint >= range.first && codePoint <= range.last;
        });
}

void requireField(const std::string& value, const std::size_t limit, const std::string& what)
{
    if (value.empty()) {
        throw std::runtime_error("the consumer's " + what + " is missing");
    }
    if (value.size() > limit) {
        throw std::runtime_error("the consumer's " + what + " is too long");
    }
    const auto* cursor = reinterpret_cast<const unsigned char*>(value.data());
    std::size_t left = value.size();
    while (left > 0) {
        unsigned long codePoint = 0;
        const int length = UTF8_getc(cursor, static_cast<int>(left), &codePoint);
        if (length <= 0) {
            throw std::runtime_error("the consumer's " + what + " is not UTF-8");
        }
        if (isForbidden(codePoint)) {
            throw std::runtime_error("the consumer's " + what + " carries control characters");
        }
        cursor += length;
        left -= static_cast<std::size_t>(length);
    }
}

}  // namespace

void requireUsableConsumer(const LoginConsumer& consumer)
{
    requireField(consumer.name, kConsumerNameMax, "name");
    if (consumer.place.empty()) {
        throw std::runtime_error("the consumer names no place");
    }
    if (consumer.place.size() > kConsumerPlacesMax) {
        throw std::runtime_error("the consumer names more than "
            + std::to_string(kConsumerPlacesMax) + " places");
    }
    for (const std::string& place : consumer.place) {
        requireField(place, kConsumerPlaceMax, "place");
    }
    requireField(consumer.role, kConsumerRoleMax, "role");
}

std::string canonicalConsumer(const LoginConsumer& consumer)
{
    requireUsableConsumer(consumer);
    const nlohmann::json object = {
        {"name", consumer.name},
        {"place", consumer.place},
        {"role", consumer.role},
    };
    return object.dump();
}

LoginConsumer readLoginConsumer(const std::string& challenge)
{
    LoginConsumer consumer;
    try {
        const Bytes raw = fromBase64(challenge);
        const nlohmann::json envelope = nlohmann::json::parse(raw.begin(), raw.end());
        if (!envelope.contains("v") || envelope.at("v").get<int>() != kLoginChallengeVersion) {
            throw std::runtime_error("it is of a version this client does not know");
        }
        if (!envelope.contains("consumer")) {
            throw std::runtime_error("it does not say who consumes the signature");
        }
        const nlohmann::json& object = envelope.at("consumer");
        consumer.name = object.value("name", std::string());
        consumer.place = object.value("place", std::vector<std::string>());
        consumer.role = object.value("role", std::string());
    } catch (const std::exception& error) {
        throw std::runtime_error(
            std::string("this is not a Bazarish login challenge: ") + error.what());
    }
    requireUsableConsumer(consumer);
    return consumer;
}

std::string signLoginBlob(
    const Identity& identity, const std::int64_t timestamp, const std::string& challenge)
{
    const auth::Headers headers = auth::signRequest(
        identity, timestamp, kLoginMethod, kLoginPath, Bytes(challenge.begin(), challenge.end()));
    const nlohmann::json blob = {
        {"k", headers.at(auth::kHeaderKeys)},
        {"t", headers.at(auth::kHeaderTimestamp)},
        {"n", headers.at(auth::kHeaderNonce)},
        {"c", headers.at(auth::kHeaderSignatureClassical)},
        {"p", headers.at(auth::kHeaderSignaturePq)},
    };
    const std::string text = blob.dump();
    return toBase64(Bytes(text.begin(), text.end()));
}

std::string verifyLoginBlob(
    const std::string& blob, const std::int64_t now, const std::string& challenge)
{
    const char* const kNotASignature
        = "this is not a signature: the field wants what your client's Signature window copied";
    nlohmann::json parsed;
    try {
        const Bytes raw = fromBase64(blob);
        parsed = nlohmann::json::parse(raw.begin(), raw.end());
    } catch (const std::exception&) {
        throw std::runtime_error(kNotASignature);
    }
    if (parsed.contains("consumer") && parsed.contains("nonce")) {
        throw std::runtime_error(
            "this is the challenge, not the signature: paste what your client copied");
    }
    auth::Headers headers;
    try {
        headers[auth::kHeaderKeys] = parsed.at("k").get<std::string>();
        headers[auth::kHeaderTimestamp] = parsed.at("t").get<std::string>();
        headers[auth::kHeaderNonce] = parsed.at("n").get<std::string>();
        headers[auth::kHeaderSignatureClassical] = parsed.at("c").get<std::string>();
        headers[auth::kHeaderSignaturePq] = parsed.at("p").get<std::string>();
    } catch (const nlohmann::json::exception&) {
        throw std::runtime_error(kNotASignature);
    }
    return auth::verifyRequest(
        headers, now, kLoginMethod, kLoginPath, Bytes(challenge.begin(), challenge.end()));
}

}  // namespace bazarish::service
