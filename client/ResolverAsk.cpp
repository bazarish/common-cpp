// Bazarish project (c) 2026
#include "ResolverAsk.hpp"

#include <bazarish/JsonRead.hpp>
#include <bazarish/ResolverChannel.hpp>

#include <nlohmann/json.hpp>

#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>

namespace bazarish::client {

namespace {

constexpr int kStatusOk = 200;

std::mutex& heldKeysMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::map<std::string, Bytes>& heldKeys()
{
    static std::map<std::string, Bytes> keys;
    return keys;
}

std::string keyIndex(const ResolverCoordinate& resolver)
{
    return resolver.rootFingerprint + "@" + resolver.dest;
}

Key fetchChannelKey(const ResolverCoordinate& resolver, const FetchTransport& transport,
    const std::int64_t now)
{
    const FetchOutcome answer = transport(resolver.dest, kChannelOp, {});
    if (!answer.ok) {
        throw std::runtime_error("the alias registry did not give its channel key: "
            + (answer.errorCode.empty() ? std::string("no answer") : answer.errorCode));
    }
    const nlohmann::json held = parseJson(std::string(answer.sealed.begin(), answer.sealed.end()));
    Key key = verifyChannelKey(fromBase64(held.at("key").get<std::string>()),
        fromBase64(held.at("delegation").get<std::string>()), resolver.rootFingerprint, now);
    const std::lock_guard<std::mutex> lock(heldKeysMutex());
    heldKeys().insert_or_assign(keyIndex(resolver), key.publicDer());
    return key;
}

std::optional<Key> heldKey(const ResolverCoordinate& resolver)
{
    const std::lock_guard<std::mutex> lock(heldKeysMutex());
    const auto found = heldKeys().find(keyIndex(resolver));
    if (found == heldKeys().end()) {
        return std::nullopt;
    }
    return Key::fromPublicDer(found->second);
}

FetchOutcome outcomeOf(const ChannelReply& reply)
{
    FetchOutcome outcome;
    outcome.ok = reply.status == kStatusOk;
    if (outcome.ok) {
        outcome.sealed = reply.body;
        return outcome;
    }
    outcome.refusal = reply.body;
    try {
        outcome.errorCode
            = parseJson(std::string(reply.body.begin(), reply.body.end())).value("errorCode", "");
    } catch (const std::exception&) {
        outcome.errorCode.clear();
    }
    if (outcome.errorCode.empty()) {
        outcome.errorCode = "HTTP_" + std::to_string(reply.status);
    }
    return outcome;
}

}  // namespace

FetchOutcome askResolver(const ResolverCoordinate& resolver, const FetchTransport& transport,
    const std::string& op, const Bytes& body, const std::int64_t now)
{
    std::optional<Key> held = heldKey(resolver);
    const bool wasHeld = held.has_value();
    const Key key = wasHeld ? std::move(*held) : fetchChannelKey(resolver, transport, now);
    SealedChannelRequest sealed = sealChannelRequest({op, body}, key);
    FetchOutcome answer = transport(resolver.dest, kSealedOp, sealed.message);
    if (!answer.ok && answer.errorCode == kChannelKeyUnknownCode && wasHeld) {
        sealed = sealChannelRequest({op, body}, fetchChannelKey(resolver, transport, now));
        answer = transport(resolver.dest, kSealedOp, sealed.message);
    }
    if (!answer.ok) {
        return answer;
    }
    const std::optional<ChannelReply> reply = openChannelReply(answer.sealed, sealed.replyKey);
    if (!reply.has_value()) {
        throw std::runtime_error("the alias registry's answer does not open");
    }
    return outcomeOf(*reply);
}

}  // namespace bazarish::client
