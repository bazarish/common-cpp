// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace bazarish {

inline constexpr char kResolverChannelPath[] = "/v1/channel";
inline constexpr char kResolverSealedPath[] = "/v1/sealed";
inline constexpr char kChannelKeyUnknownCode[] = "CHANNEL_KEY_UNKNOWN";
inline constexpr char kResolveOp[] = "resolve";
// Every reply is padded to a multiple of this, so a found name and a refusal look alike.
inline constexpr std::size_t kChannelReplyStepBytes = 32 * 1024;

// The resolver's channel key, signed by its delegated key; the key lives until the resolver restarts.
Bytes signChannelKey(const Key& channelKey, std::int64_t issuedAt, const Identity& delegated);
Key verifyChannelKey(const Bytes& signedKey, const Bytes& delegationDer,
    const std::string& trustedRootFingerprint, std::int64_t now);

struct ChannelRequest {
    std::string op;
    Bytes body;
};

struct SealedChannelRequest {
    Bytes message;
    Bytes replyKey;
};

struct OpenedChannelRequest {
    ChannelRequest request;
    Bytes replyKey;
};

struct ChannelReply {
    int status = 0;
    Bytes body;
};

SealedChannelRequest sealChannelRequest(const ChannelRequest& request, const Key& channelKey);
std::optional<OpenedChannelRequest> openChannelRequest(const Bytes& message, const Key& channelKey);

Bytes sealChannelReply(const ChannelReply& reply, const Bytes& replyKey);
std::optional<ChannelReply> openChannelReply(const Bytes& message, const Bytes& replyKey);

}  // namespace bazarish
