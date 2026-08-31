// Bazarish project (c) 2026
#include "bazarish/Portal.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace bazarish::service {

namespace {

// Consumer fields are read by a person. A control character would let a name
// paint a line the consumer never wrote.
bool hasControlCharacters(const std::string& text)
{
    for (const unsigned char character : text) {
        if (character < 0x20 || character == 0x7F) {
            return true;
        }
    }
    return false;
}

void requireField(const std::string& value, const std::size_t limit, const std::string& what)
{
    if (value.empty()) {
        throw std::runtime_error("the consumer's " + what + " is missing");
    }
    if (value.size() > limit) {
        throw std::runtime_error("the consumer's " + what + " is too long");
    }
    if (hasControlCharacters(value)) {
        throw std::runtime_error("the consumer's " + what + " carries control characters");
    }
}

}  // namespace

void requireUsableConsumer(const LoginConsumer& consumer)
{
    requireField(consumer.name, kConsumerNameMax, "name");
    requireField(consumer.place, kConsumerPlaceMax, "place");
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
        consumer.place = object.value("place", std::string());
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
        {"c", headers.at(auth::kHeaderSignatureClassical)},
        {"p", headers.at(auth::kHeaderSignaturePq)},
    };
    const std::string text = blob.dump();
    return toBase64(Bytes(text.begin(), text.end()));
}

std::string verifyLoginBlob(
    const std::string& blob, const std::int64_t now, const std::string& challenge)
{
    const Bytes raw = fromBase64(blob);
    const nlohmann::json parsed = nlohmann::json::parse(raw.begin(), raw.end());
    auth::Headers headers;
    headers[auth::kHeaderKeys] = parsed.at("k").get<std::string>();
    headers[auth::kHeaderTimestamp] = parsed.at("t").get<std::string>();
    headers[auth::kHeaderSignatureClassical] = parsed.at("c").get<std::string>();
    headers[auth::kHeaderSignaturePq] = parsed.at("p").get<std::string>();
    return auth::verifyRequest(
        headers, now, kLoginMethod, kLoginPath, Bytes(challenge.begin(), challenge.end()));
}

}  // namespace bazarish::service
