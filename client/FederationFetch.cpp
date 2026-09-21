// Bazarish project (c) 2026
#include "FederationFetch.hpp"

#include "I2pRouter.hpp"

#include <bazarish/FederationFrame.hpp>

#include <chrono>
#include <memory>
#include <stdexcept>

namespace bazarish::client {

// A cold dest needs its own tunnels before it can dial; a warm one already has
// them. Separate from the dial timeout, which is about reaching the far side.
constexpr int kOwnTunnelsSeconds = 180;
constexpr int kDialSeconds = 90;
// How long the answer may take once the request is on the peer's server. It
// answers a card from its own store, so this is a bound on a far side that took
// the request and went quiet - not on any work it has to do.
constexpr int kReplySeconds = 90;

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

FetchOutcome fetchOver(bazarish::i2p::Endpoint& endpoint, const std::string& dest,
    const std::string& op, const Bytes& sealed)
{
    auto stream = endpoint.connect(dest, std::chrono::seconds(kDialSeconds));
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
