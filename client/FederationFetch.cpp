// Bazarish project (c) 2026
#include "FederationFetch.hpp"

#include "AttemptBudget.hpp"
#include "I2pRouter.hpp"
#include "ResolverAsk.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/FederationFrame.hpp>
#include <bazarish/I2pHttp.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/ResolverChannel.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <thread>

namespace bazarish::client {

constexpr int kReplySeconds = 90;
constexpr int kFetchAttempts = 3;
constexpr int kLeastDialSeconds = 10;
constexpr int kLeastReplySeconds = 20;
constexpr int kFetchRetryGapSeconds[kFetchAttempts - 1] = {2, 6};
constexpr int kFetchRunSeconds = kDialSeconds + kReplySeconds;
constexpr char kContactLookupLabel[] = "Contact lookup";
constexpr char kSignInLabel[] = "Sign-in";

namespace {

thread_local std::function<void(FetchStage)> stageSink;

void sayStage(const FetchStage stage)
{
    if (stageSink) {
        stageSink(stage);
    }
}

std::shared_ptr<bazarish::i2p::Endpoint> takeThrowawayDest(bazarish::i2p::Router& router,
    const bazarish::i2p::Privacy privacy, const std::string& owner, const std::string& target,
    const char* const label = kContactLookupLabel)
{
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint = acquireWarmDest(privacy);
    if (endpoint) {
        sayStage(FetchStage::eTakingDest);
        router.retagEndpoint(*endpoint, label, owner);
        return endpoint;
    }
    sayStage(FetchStage::eBuildingDest);
    bazarish::i2p::EndpointConfig config;
    config.privacy = privacy;
    config.published = false;
    config.label = label;
    config.owner = owner;
    config.target = target;
    endpoint = router.createEndpoint(config);
    if (!endpoint->waitReady(std::chrono::seconds(kOwnTunnelsSeconds))) {
        throw std::runtime_error("federation fetch: this device has no I2P tunnels yet");
    }
    return endpoint;
}

enum class Face { eFederationFrame, eResolverHttp };

void sendI2pHttpRequest(bazarish::i2p::Stream& stream, const std::string& method,
    const std::string& host, const std::string& path,
    const std::map<std::string, std::string>& headers, const std::string& body)
{
    stream.writeAll(viewOf(buildI2pHttpRequest(method, host, path, headers, body.size())));
    if (!body.empty()) {
        stream.writeAll(viewOf(body));
    }
}

// Null when the host is not reached in time; the read deadline is set for what follows.
std::unique_ptr<bazarish::i2p::Stream> dialI2pHttp(bazarish::i2p::Endpoint& endpoint,
    const std::string& host, const std::chrono::seconds dialFor,
    const std::chrono::seconds waitFor)
{
    sayStage(FetchStage::eReaching);
    std::unique_ptr<bazarish::i2p::Stream> stream = endpoint.connect(host, dialFor);
    if (stream) {
        stream->setReadTimeout(waitFor);
    }
    return stream;
}

FetchOutcome askResolverHttp(bazarish::i2p::Stream& stream, const std::string& host,
    const std::string& op, const Bytes& body)
{
    std::string method;
    std::string path;
    std::string payload(body.begin(), body.end());
    if (op == kChannelOp) {
        method = "GET";
        path = kResolverChannelPath;
        payload.clear();
    } else if (op == kSealedOp) {
        method = "POST";
        path = kResolverSealedPath;
    } else {
        throw std::logic_error("the alias registry is asked only through its channel, not " + op);
    }
    const std::map<std::string, std::string> headers
        = payload.empty() ? std::map<std::string, std::string>{}
                          : std::map<std::string, std::string>{
                                {"Content-Type", "application/octet-stream"}};
    sendI2pHttpRequest(stream, method, host, path, headers, payload);
    const I2pHttpResponse answer = readI2pHttpResponse(stream, kMaxResolverAnswerBytes);

    FetchOutcome outcome;
    outcome.ok = answer.status == kI2pHttpOk;
    if (outcome.ok) {
        outcome.sealed.assign(answer.body.begin(), answer.body.end());
        return outcome;
    }
    outcome.refusal.assign(answer.body.begin(), answer.body.end());
    try {
        outcome.errorCode
            = parseJson(answer.body).value("errorCode", std::string());
    } catch (const std::exception&) {
        outcome.errorCode = "HTTP_" + std::to_string(answer.status);
    }
    if (outcome.errorCode.empty()) {
        outcome.errorCode = "HTTP_" + std::to_string(answer.status);
    }
    return outcome;
}

FetchOutcome fetchOnce(bazarish::i2p::Endpoint& endpoint, const std::string& dest,
    const std::string& op, const Bytes& sealed, const std::chrono::seconds dialFor,
    const std::chrono::seconds waitFor, std::chrono::seconds& dialTook, const Face face)
{
    const auto dialStarted = std::chrono::steady_clock::now();
    const std::unique_ptr<bazarish::i2p::Stream> stream
        = dialI2pHttp(endpoint, dest, dialFor, waitFor);
    dialTook = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - dialStarted);
    if (!stream) {
        throw std::runtime_error("federation fetch: cannot reach " + dest);
    }

    sayStage(FetchStage::eWaiting);
    if (face == Face::eResolverHttp) {
        return askResolverHttp(*stream, dest, op, sealed);
    }
    const FederationFetchResult reply = federationSendFetch(*stream, op, sealed);
    FetchOutcome outcome;
    outcome.ok = reply.ok;
    outcome.sealed = reply.sealed;
    outcome.errorCode = reply.errorCode;
    return outcome;
}

FetchOutcome fetchOver(bazarish::i2p::Endpoint& endpoint, const std::string& dest,
    const std::string& op, const Bytes& sealed, const Face face)
{
    const AttemptBudget budget{std::chrono::seconds(kFetchRunSeconds)};
    std::chrono::seconds dialTook{kDialSeconds};
    for (int attempt = 1;; ++attempt) {
        const std::chrono::seconds left = budget.left();
        try {
            return fetchOnce(endpoint, dest, op, sealed,
                std::min(left, std::chrono::seconds(kDialSeconds)),
                std::min(left, std::chrono::seconds(kReplySeconds)), dialTook, face);
        } catch (const std::exception& error) {
            const auto gap = attempt < kFetchAttempts
                ? std::chrono::seconds(kFetchRetryGapSeconds[attempt - 1])
                : std::chrono::seconds(0);
            const auto next = std::max(dialTook, std::chrono::seconds(kLeastDialSeconds))
                + std::chrono::seconds(kLeastReplySeconds);
            if (attempt >= kFetchAttempts || !budget.pays(gap, next)) {
                throw;
            }
            sayStage(FetchStage::eAskingAgain);
            bazarish::log::info("federation fetch: no answer from {} on try {}, asking again: {}",
                bazarish::log::redact(dest), attempt, error.what());
            std::this_thread::sleep_for(gap);
        }
    }
}

}  // namespace

void tellFetchStages(std::function<void(FetchStage)> tell)
{
    stageSink = std::move(tell);
}

FetchOutcome federationFetchOverI2p(bazarish::i2p::Router& router, const std::string& dest,
    const std::string& op, const Bytes& sealed, const bazarish::i2p::Privacy privacy,
    const std::string& owner)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
        = takeThrowawayDest(router, privacy, owner, dest);
    return fetchOver(*endpoint, dest, op, sealed, Face::eFederationFrame);
}

FetchOutcome resolverFetchOverI2p(bazarish::i2p::Router& router, const std::string& host,
    const std::string& op, const Bytes& body, const bazarish::i2p::Privacy privacy,
    const std::string& owner)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
        = takeThrowawayDest(router, privacy, owner, host);
    return fetchOver(*endpoint, host, op, body, Face::eResolverHttp);
}

std::optional<int> postLoginOverI2p(bazarish::i2p::Router& router,
    const service::LoginCallback& callback, const std::string& sealedAnswer,
    const bazarish::i2p::Privacy privacy, const std::string& owner)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
        = takeThrowawayDest(router, privacy, owner, callback.host, kSignInLabel);
    const auto stream = dialI2pHttp(*endpoint, callback.host, std::chrono::seconds(kDialSeconds),
        std::chrono::seconds(kReplySeconds));
    if (!stream) {
        return std::nullopt;
    }
    sendI2pHttpRequest(*stream, "POST", callback.host, callback.path,
        {{"Content-Type", "application/json"}}, sealedAnswer);
    sayStage(FetchStage::eWaiting);
    return readI2pHttpHead(*stream).status;
}

std::optional<Bytes> getLoginChallengeOverI2p(bazarish::i2p::Router& router,
    const service::LoginCallback& address, const bazarish::i2p::Privacy privacy,
    const std::string& owner, const std::atomic<bool>& cancelled)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
        = takeThrowawayDest(router, privacy, owner, address.host, kSignInLabel);
    if (cancelled.load()) {
        return std::nullopt;
    }
    const auto stream = dialI2pHttp(*endpoint, address.host, std::chrono::seconds(kDialSeconds),
        std::chrono::seconds(kReplySeconds));
    if (!stream || cancelled.load()) {
        return std::nullopt;
    }
    sendI2pHttpRequest(*stream, "GET", address.host, address.path, {}, {});
    sayStage(FetchStage::eWaiting);
    const I2pHttpResponse response
        = readI2pHttpResponse(*stream, service::kLoginChallengeMax + kAeadNonceBytes + kAeadTagBytes);
    if (response.status != kI2pHttpOk) {
        throw std::runtime_error("the site answered HTTP " + std::to_string(response.status));
    }
    return Bytes(response.body.begin(), response.body.end());
}

FetchTransport resolverHeldDest(
    bazarish::i2p::Router& router, const bazarish::i2p::Privacy privacy, const std::string& owner)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> held
        = takeThrowawayDest(router, privacy, owner, std::string());
    return [held](const std::string& host, const std::string& op, const Bytes& body) {
        return fetchOver(*held, host, op, body, Face::eResolverHttp);
    };
}

}  // namespace bazarish::client
