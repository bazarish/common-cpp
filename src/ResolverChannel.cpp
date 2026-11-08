// Bazarish project (c) 2026
#include "bazarish/ResolverChannel.hpp"

#include "bazarish/Certificates.hpp"
#include "bazarish/Hybrid.hpp"
#include "bazarish/JsonRead.hpp"
#include "bazarish/KeyedSeal.hpp"
#include "bazarish/Log.hpp"
#include "bazarish/Padding.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace bazarish {

namespace {

constexpr int kChannelVersion = 1;
constexpr char kChannelKeyType[] = "resolver-channel";
constexpr char kReplyLabel[] = "bazarish resolver reply v1";

Bytes cbor(const nlohmann::json& value)
{
    const std::vector<std::uint8_t> encoded = nlohmann::json::to_cbor(value);
    return Bytes(encoded.begin(), encoded.end());
}

Bytes binaryOf(const nlohmann::json& value)
{
    const nlohmann::json::binary_t& binary = value.get_binary();
    return Bytes(binary.begin(), binary.end());
}

Bytes paddedReply(const Bytes& payload)
{
    Bytes padded = padToLadder(payload);
    const std::size_t steps = (padded.size() + kChannelReplyStepBytes - 1) / kChannelReplyStepBytes;
    padded.resize(steps * kChannelReplyStepBytes, 0);
    return padded;
}

}  // namespace

Bytes signChannelKey(const Key& channelKey, const std::int64_t issuedAt, const Identity& delegated)
{
    return hybrid::signJson({{"v", kChannelVersion}, {"t", kChannelKeyType},
                                {"key", toBase64(channelKey.publicDer())}, {"issuedAt", issuedAt}},
        delegated);
}

Key verifyChannelKey(const Bytes& signedKey, const Bytes& delegationDer,
    const std::string& trustedRootFingerprint, const std::int64_t now)
{
    const DelegationCertificate delegation = DelegationCertificate::verify(delegationDer);
    if (delegation.root != trustedRootFingerprint) {
        throw std::runtime_error("channel key: delegation is not from the trusted root");
    }
    if (delegation.issuedAt > now + kClockSkewSeconds || now > delegation.notAfter) {
        throw std::runtime_error("channel key: delegation is not valid now");
    }
    const hybrid::VerifiedJson verified = hybrid::verifyJson(signedKey);
    if (verified.identityFingerprint != delegation.delegatedFingerprint()) {
        throw std::runtime_error("channel key: signer is not the delegated key");
    }
    if (verified.body.at("v").get<int>() != kChannelVersion
        || verified.body.at("t").get<std::string>() != kChannelKeyType) {
        throw std::runtime_error("channel key: not a channel key");
    }
    if (verified.body.at("issuedAt").get<std::int64_t>() > now + kClockSkewSeconds) {
        throw std::runtime_error("channel key: dated in the future");
    }
    return Key::fromPublicDer(fromBase64(verified.body.at("key").get<std::string>()));
}

SealedChannelRequest sealChannelRequest(const ChannelRequest& request, const Key& channelKey)
{
    SealedChannelRequest sealed;
    sealed.replyKey = newLinkKey();
    const Bytes plain = cbor({{"op", request.op}, {"body", nlohmann::json::binary(request.body)},
        {"replyKey", nlohmann::json::binary(sealed.replyKey)}});
    sealed.message = hybrid::seal(padToLadder(plain), channelKey);
    return sealed;
}

std::optional<OpenedChannelRequest> openChannelRequest(const Bytes& message, const Key& channelKey)
{
    try {
        const nlohmann::json plain = parseCbor(unpadFromLadder(hybrid::unseal(message, channelKey)));
        OpenedChannelRequest opened;
        opened.request.op = plain.at("op").get<std::string>();
        opened.request.body = binaryOf(plain.at("body"));
        opened.replyKey = binaryOf(plain.at("replyKey"));
        if (opened.replyKey.size() != kLinkKeyBytes) {
            return std::nullopt;
        }
        return opened;
    } catch (const std::exception& error) {
        log::debug("a channel request that does not open: {}", error.what());
        return std::nullopt;
    }
}

Bytes sealChannelReply(const ChannelReply& reply, const Bytes& replyKey)
{
    const Bytes plain
        = cbor({{"status", reply.status}, {"body", nlohmann::json::binary(reply.body)}});
    return KeyedSeal(replyKey, kReplyLabel).seal(paddedReply(plain));
}

std::optional<ChannelReply> openChannelReply(const Bytes& message, const Bytes& replyKey)
{
    const std::optional<Bytes> padded = KeyedSeal(replyKey, kReplyLabel).open(message);
    if (!padded.has_value()) {
        return std::nullopt;
    }
    const nlohmann::json plain = parseCbor(unpadFromLadder(*padded));
    return ChannelReply{plain.at("status").get<int>(), binaryOf(plain.at("body"))};
}

}  // namespace bazarish
