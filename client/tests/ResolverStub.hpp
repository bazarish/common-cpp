// Bazarish project (c) 2026
#pragma once

#include "Client.hpp"
#include "ResolverAsk.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/ResolverChannel.hpp>

#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace bazarish::client {

// The resolver's sealed channel in front of a fake that answers plain ops.
class ResolverStub {
public:
    using Plain = std::function<FetchOutcome(const std::string& op, const Bytes& body)>;

    ResolverStub(const Identity& delegated, Bytes delegationDer)
        : delegated_(delegated)
        , delegationDer_(std::move(delegationDer))
        , key_(Key::generateSealing())
    {
    }

    static bool asks(const std::string& op) { return op == kChannelOp || op == kSealedOp; }

    FetchOutcome answer(
        const std::string& op, const Bytes& body, const Plain& plain, const std::int64_t now)
    {
        FetchOutcome outcome;
        if (op == kChannelOp) {
            const std::string held = nlohmann::json{
                {"key", toBase64(signChannelKey(key_, now, delegated_))},
                {"delegation", toBase64(delegationDer_)}}.dump();
            outcome.ok = true;
            outcome.sealed = Bytes(held.begin(), held.end());
            return outcome;
        }
        const std::optional<OpenedChannelRequest> opened = openChannelRequest(body, key_);
        if (!opened.has_value()) {
            outcome.errorCode = kChannelKeyUnknownCode;
            return outcome;
        }
        const FetchOutcome inner = plain(opened->request.op, opened->request.body);
        ChannelReply reply;
        reply.status = inner.ok ? kOk : kRefused;
        if (inner.ok) {
            reply.body = inner.sealed;
        } else if (!inner.refusal.empty()) {
            nlohmann::json refusal = nlohmann::json::parse(inner.refusal);
            refusal["errorCode"] = inner.errorCode;
            const std::string text = refusal.dump();
            reply.body = Bytes(text.begin(), text.end());
        } else {
            const std::string text = nlohmann::json{{"errorCode", inner.errorCode}}.dump();
            reply.body = Bytes(text.begin(), text.end());
        }
        outcome.ok = true;
        outcome.sealed = sealChannelReply(reply, opened->replyKey);
        return outcome;
    }

    void restart() { key_ = Key::generateSealing(); }

private:
    static constexpr int kOk = 200;
    static constexpr int kRefused = 400;

    const Identity& delegated_;
    const Bytes delegationDer_;
    Key key_;
};

}  // namespace bazarish::client
