// Bazarish project (c) 2026
#include "FederationFetch.hpp"

#include "I2pRouter.hpp"

#include <bazarish/FederationFrame.hpp>
#include <bazarish/I2pHttp.hpp>
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

// A cold dest needs its own tunnels before it can dial; a warm one already has
// them. Separate from the dial timeout, which is about reaching the far side.
constexpr int kOwnTunnelsSeconds = 180;
constexpr int kDialSeconds = 90;
// How long the answer may take once the request is on the peer's server. It
// answers a card from its own store, so this is a bound on a far side that took
// the request and went quiet - not on any work it has to do.
constexpr int kReplySeconds = 90;
// A fetch that got no answer at all is tried again, the way a delivery is: a
// destination published a moment ago, a lease about to be replaced, or a stream
// the far side dropped all end the same way, and all of them are gone by the
// next try. Only silence is repeated - a peer that answered has answered.
constexpr int kFetchAttempts = 3;
// The resolver's op for a public name lookup, and the one status that means it
// answered. Everything else it says names itself in the body.
constexpr const char* kResolveOp = "resolve";
constexpr int kHttpOk = 200;
// What a try must still be able to pay for to be worth starting: a dial at
// least this long even when the last one was quicker, and an answer after it.
constexpr int kLeastDialSeconds = 10;
constexpr int kLeastReplySeconds = 20;
constexpr int kFetchRetryGapSeconds[kFetchAttempts - 1] = {2, 6};
// The whole lookup, however many tries fit inside it - and one try that spends
// its whole dial and its whole wait already fills it. So a peer that is simply
// not there is reported as fast as it ever was, while a stream that died in
// seconds leaves room to ask again. A try is started only if the budget can pay
// for its dial, because a dial with no time in it reaches nobody.
constexpr int kFetchRunSeconds = kDialSeconds + kReplySeconds;

namespace {

// Per thread, because a fetch runs on the thread that asked for it and reports
// to whoever is watching that one.
thread_local std::function<void(const std::string&)> stageSink;

void sayStage(const std::string& stage)
{
    if (stageSink) {
        stageSink(stage);
    }
}

// A warm, pre-built throwaway dest from the pool when one is ready (no cold
// tunnel-build latency), else a fresh one built cold. Either way the dest is
// single-use and belongs to whoever asked for it; connecting out does not need a
// published leaseset.
std::shared_ptr<bazarish::i2p::Endpoint> takeThrowawayDest(
    bazarish::i2p::Router& router, const bazarish::i2p::Privacy privacy, const std::string& owner)
{
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint = acquireWarmDest();
    if (endpoint) {
        sayStage("Taking a destination to ask from");
        // A spare belongs to nobody while it waits; from here it is this
        // account's lookup, and the status view should say so.
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
        // A dest built for this call has no tunnels yet. Dialing anyway fails in a
        // way that reads as "the peer is unreachable", which it is not.
        throw std::runtime_error("federation fetch: this device has no I2P tunnels yet");
    }
    return endpoint;
}

// What is spoken once the stream is open. A server of this project answers a
// federation frame; the alias resolver is a web service inside I2P, reached
// through an i2pd tunnel, and answers HTTP. The dialling, the throwaway
// destination and the retries are the same for both, which is why they meet
// here rather than in two copies of this file.
enum class Face { eFederationFrame, eResolverHttp };

// The resolver's HTTP API, in the shape each op is written in: a resolve is a
// GET of the name, an owner's op is a POST of what they signed. The answer's
// body is the reply itself, which is what the callers already expect to find in
// `sealed`; a refusal names itself in the body it comes with.
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
    const I2pHttpResponse answer = readI2pHttpResponse(stream);

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
    // A peer that accepts the stream and then says nothing must not hold this
    // thread: an add sits at "preparing" for as long as this waits.
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
    // What the dial actually cost last time. A peer whose leaseset is already in
    // hand is dialled in a second or two, and holding the whole dial allowance
    // back for a try that will not need it is what turned three tries into one
    // whenever the first one was met with silence.
    std::chrono::seconds dialTook{kDialSeconds};
    for (int attempt = 1;; ++attempt) {
        const auto left = std::chrono::duration_cast<std::chrono::seconds>(
            deadline - std::chrono::steady_clock::now());
        try {
            return fetchOnce(endpoint, dest, op, sealed,
                std::min(left, std::chrono::seconds(kDialSeconds)),
                std::min(left, std::chrono::seconds(kReplySeconds)), dialTook, face);
        } catch (const std::exception& error) {
            // The last one's reason is the one the user is told, so it is thrown
            // rather than turned into a message of this loop's own.
            const auto gap = attempt < kFetchAttempts
                ? std::chrono::seconds(kFetchRetryGapSeconds[attempt - 1])
                : std::chrono::seconds(0);
            // A try is worth starting only if what is left can pay for the dial
            // it now knows the price of, and for an answer after it.
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
    // Taken here rather than on first use, so the returned callable holds the
    // destination and nothing else: it outlives this call on another thread, and
    // a router reference kept across that could outlive the router. The dest goes
    // when the transport does.
    const std::shared_ptr<bazarish::i2p::Endpoint> held
        = takeThrowawayDest(router, privacy, owner);
    return [held](const std::string& dest, const std::string& op, const Bytes& sealed) {
        return fetchOver(*held, dest, op, sealed, Face::eFederationFrame);
    };
}

}  // namespace bazarish::client
