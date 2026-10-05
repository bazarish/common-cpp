// Bazarish project (c) 2026
#include "FederationFetch.hpp"

#include "I2pRouter.hpp"

#include <bazarish/FederationFrame.hpp>
#include <bazarish/I2pHttp.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <thread>

namespace bazarish::client {

constexpr int kOwnTunnelsSeconds = 180;
constexpr int kDialSeconds = 90;
constexpr int kReplySeconds = 90;
constexpr int kFetchAttempts = 3;
constexpr const char* kResolveOp = "resolve";
constexpr int kHttpOk = 200;
constexpr int kLeastDialSeconds = 10;
constexpr int kLeastReplySeconds = 20;
constexpr int kFetchRetryGapSeconds[kFetchAttempts - 1] = {2, 6};
constexpr int kFetchRunSeconds = kDialSeconds + kReplySeconds;

namespace {

thread_local std::function<void(const std::string&)> stageSink;

void sayStage(const std::string& stage)
{
    if (stageSink) {
        stageSink(stage);
    }
}

std::shared_ptr<bazarish::i2p::Endpoint> takeThrowawayDest(
    bazarish::i2p::Router& router, const bazarish::i2p::Privacy privacy, const std::string& owner)
{
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint = acquireWarmDest();
    if (endpoint) {
        sayStage("Taking a destination to ask from");
        router.retagEndpoint(*endpoint, "Contact lookup", owner);
        return endpoint;
    }
    sayStage("Building a destination to ask from");
    bazarish::i2p::EndpointConfig config;
    config.privacy = privacy;
    config.published = false;
    config.label = "Contact lookup";
    config.owner = owner;
    endpoint = router.createEndpoint(config);
    if (!endpoint->waitReady(std::chrono::seconds(kOwnTunnelsSeconds))) {
        throw std::runtime_error("federation fetch: this device has no I2P tunnels yet");
    }
    return endpoint;
}

enum class Face { eFederationFrame, eResolverHttp };

FetchOutcome askResolver(bazarish::i2p::Stream& stream, const std::string& host,
    const std::string& op, const Bytes& body)
{
    std::string method = "POST";
    std::string path = "/v1/op/" + op;
    std::string payload(body.begin(), body.end());
    if (op == kResolveOp) {
        const nlohmann::json query = nlohmann::json::parse(payload);
        method = "GET";
        path = "/v1/alias/" + query.at("alias").get<std::string>();
        payload.clear();
    }
    const std::map<std::string, std::string> headers
        = payload.empty() ? std::map<std::string, std::string>{}
                          : std::map<std::string, std::string>{
                                {"Content-Type", "application/octet-stream"}};
    const std::string head = buildI2pHttpRequest(method, host, path, headers, payload.size());
    stream.writeAll(head.data(), head.size());
    if (!payload.empty()) {
        stream.writeAll(payload.data(), payload.size());
    }
    const I2pHttpResponse answer = readI2pHttpResponse(stream, kMaxResolverAnswerBytes);

    FetchOutcome outcome;
    outcome.ok = answer.status == kHttpOk;
    if (outcome.ok) {
        outcome.sealed.assign(answer.body.begin(), answer.body.end());
        return outcome;
    }
    try {
        outcome.errorCode
            = nlohmann::json::parse(answer.body).value("errorCode", std::string());
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
    sayStage("Reaching their server");
    const auto dialStarted = std::chrono::steady_clock::now();
    auto stream = endpoint.connect(dest, dialFor);
    dialTook = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - dialStarted);
    if (!stream) {
        throw std::runtime_error("federation fetch: cannot reach " + dest);
    }
    stream->setReadTimeout(waitFor);

    sayStage("Waiting for their answer");
    if (face == Face::eResolverHttp) {
        return askResolver(*stream, dest, op, sealed);
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
    const auto deadline
        = std::chrono::steady_clock::now() + std::chrono::seconds(kFetchRunSeconds);
    std::chrono::seconds dialTook{kDialSeconds};
    for (int attempt = 1;; ++attempt) {
        const auto left = std::chrono::duration_cast<std::chrono::seconds>(
            deadline - std::chrono::steady_clock::now());
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
            if (attempt >= kFetchAttempts
                || std::chrono::steady_clock::now() + gap + next > deadline) {
                throw;
            }
            sayStage("No answer; asking again");
            bazarish::log::info("federation fetch: no answer from {} on try {}, asking again: {}",
                bazarish::log::redact(dest), attempt, error.what());
            std::this_thread::sleep_for(gap);
        }
    }
}

}  // namespace

void tellFetchStages(std::function<void(const std::string&)> tell)
{
    stageSink = std::move(tell);
}

FetchOutcome federationFetchOverI2p(bazarish::i2p::Router& router, const std::string& dest,
    const std::string& op, const Bytes& sealed, const bazarish::i2p::Privacy privacy,
    const std::string& owner)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
        = takeThrowawayDest(router, privacy, owner);
    return fetchOver(*endpoint, dest, op, sealed, Face::eFederationFrame);
}

FetchOutcome resolverFetchOverI2p(bazarish::i2p::Router& router, const std::string& host,
    const std::string& op, const Bytes& body, const bazarish::i2p::Privacy privacy,
    const std::string& owner)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
        = takeThrowawayDest(router, privacy, owner);
    return fetchOver(*endpoint, host, op, body, Face::eResolverHttp);
}

FetchTransport resolverHeldDest(
    bazarish::i2p::Router& router, const bazarish::i2p::Privacy privacy, const std::string& owner)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> held
        = takeThrowawayDest(router, privacy, owner);
    return [held](const std::string& host, const std::string& op, const Bytes& body) {
        return fetchOver(*held, host, op, body, Face::eResolverHttp);
    };
}

FetchTransport federationHeldDest(
    bazarish::i2p::Router& router, const bazarish::i2p::Privacy privacy, const std::string& owner)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> held
        = takeThrowawayDest(router, privacy, owner);
    return [held](const std::string& dest, const std::string& op, const Bytes& sealed) {
        return fetchOver(*held, dest, op, sealed, Face::eFederationFrame);
    };
}

}  // namespace bazarish::client
