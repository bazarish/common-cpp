// Bazarish project (c) 2026
#include "FederationFetch.hpp"

#include "I2pRouter.hpp"

#include <bazarish/FederationFrame.hpp>
#include <bazarish/Log.hpp>

#include <algorithm>
#include <chrono>
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
constexpr int kFetchRetryGapSeconds[kFetchAttempts - 1] = {2, 6};
// The whole lookup, however many tries fit inside it - and one try that spends
// its whole dial and its whole wait already fills it. So a peer that is simply
// not there is reported as fast as it ever was, while a stream that died in
// seconds leaves room to ask again. A try is started only if the budget can pay
// for its dial, because a dial with no time in it reaches nobody.
constexpr int kFetchRunSeconds = kDialSeconds + kReplySeconds;

namespace {

// A warm, pre-built throwaway dest from the pool when one is ready (no cold
// tunnel-build latency), else a fresh one built cold. Either way the dest is
// single-use and belongs to whoever asked for it; connecting out does not need a
// published leaseset.
std::shared_ptr<bazarish::i2p::Endpoint> takeThrowawayDest(
    bazarish::i2p::Router& router, const bazarish::i2p::Privacy privacy, const std::string& owner)
{
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint = acquireWarmDest();
    if (endpoint) {
        // A spare belongs to nobody while it waits; from here it is this
        // account's lookup, and the status view should say so.
        router.retagEndpoint(*endpoint, "Contact lookup", owner);
        return endpoint;
    }
    endpoint = router.createEndpoint(bazarish::i2p::EndpointConfig{
        router.generateKeys(), privacy, bazarish::i2p::kDefaultTunnelQuantity, false,
        "Contact lookup", owner});
    if (!endpoint->waitReady(std::chrono::seconds(kOwnTunnelsSeconds))) {
        // A dest built for this call has no tunnels yet. Dialing anyway fails in a
        // way that reads as "the peer is unreachable", which it is not.
        throw std::runtime_error("federation fetch: this device has no I2P tunnels yet");
    }
    return endpoint;
}

FetchOutcome fetchOnce(bazarish::i2p::Endpoint& endpoint, const std::string& dest,
    const std::string& op, const Bytes& sealed, const std::chrono::seconds dialFor)
{
    auto stream = endpoint.connect(dest, dialFor);
    if (!stream) {
        throw std::runtime_error("federation fetch: cannot reach " + dest);
    }
    // A peer that accepts the stream and then says nothing must not hold this
    // thread: an add sits at "preparing" for as long as this waits.
    stream->setReadTimeout(std::chrono::seconds(kReplySeconds));

    const FederationFetchResult reply = federationSendFetch(*stream, op, sealed);
    FetchOutcome outcome;
    outcome.ok = reply.ok;
    outcome.sealed = reply.sealed;
    outcome.errorCode = reply.errorCode;
    return outcome;
}

FetchOutcome fetchOver(bazarish::i2p::Endpoint& endpoint, const std::string& dest,
    const std::string& op, const Bytes& sealed)
{
    const auto deadline
        = std::chrono::steady_clock::now() + std::chrono::seconds(kFetchRunSeconds);
    for (int attempt = 1;; ++attempt) {
        const auto left = std::chrono::duration_cast<std::chrono::seconds>(
            deadline - std::chrono::steady_clock::now());
        try {
            return fetchOnce(endpoint, dest, op, sealed,
                std::min(left, std::chrono::seconds(kDialSeconds)));
        } catch (const std::exception& error) {
            // The last one's reason is the one the user is told, so it is thrown
            // rather than turned into a message of this loop's own.
            const auto gap = attempt < kFetchAttempts
                ? std::chrono::seconds(kFetchRetryGapSeconds[attempt - 1])
                : std::chrono::seconds(0);
            if (attempt >= kFetchAttempts
                || std::chrono::steady_clock::now() + gap + std::chrono::seconds(kDialSeconds)
                    > deadline) {
                throw;
            }
            bazarish::log::info("federation fetch: no answer from {} on try {}, asking again: {}",
                bazarish::log::redact(dest), attempt, error.what());
            std::this_thread::sleep_for(gap);
        }
    }
}

}  // namespace

FetchOutcome federationFetchOverI2p(bazarish::i2p::Router& router, const std::string& dest,
    const std::string& op, const Bytes& sealed, const bazarish::i2p::Privacy privacy,
    const std::string& owner)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
        = takeThrowawayDest(router, privacy, owner);
    return fetchOver(*endpoint, dest, op, sealed);
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
        return fetchOver(*held, dest, op, sealed);
    };
}

}  // namespace bazarish::client
