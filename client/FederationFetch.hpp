// Bazarish project (c) 2026
#pragma once

#include "Client.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include <functional>
#include <string>

namespace bazarish::client {

// Where a fetch says what it is doing, for whoever started it on this thread.
// A fetch is a dial and then a wait, and one that says "resolving" for both
// leaves a person watching an add with no idea which of the two is slow. Set
// for the length of a call and cleared after; a thread that sets none is told
// nothing.
void tellFetchStages(std::function<void(const std::string&)> tell);

// Speaks one federation fetch frame to a .b32.i2p destination over a FRESH
// throwaway destination on the embedded router (the direct path: our own server
// is never involved, and the throwaway destination keeps the dial unlinkable).
// The frame mirrors the server's federationServeOnce: a single JSON header line
// {op, sealed} out, a single JSON header line {ok, sealed?, errorCode?} back.
// Used for the card fetch (dial the contact's serving server) and the alias
// resolve (dial the central resolver). Building the destination + tunnels carries
// I2P latency. Throws on any transport failure (unreachable destination,
// malformed frame) so the caller can fall back to the proxy.
FetchOutcome federationFetchOverI2p(bazarish::i2p::Router& router, const std::string& dest,
    const std::string& op, const Bytes& sealed,
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax,
    const std::string& owner = {});

// The alias resolver, which is not a server of this project speaking its
// federation frame but a web service inside I2P: an i2pd tunnel in front of it
// carries plain HTTP to it. Same throwaway destination, same dial and the same
// retries; what differs is what is said once the stream is open. `host` is the
// address the resolver answers at, `op` is "resolve" or one of the owner's own
// ops, and the answer's body comes back in `sealed` exactly as the frame's did.
FetchOutcome resolverFetchOverI2p(bazarish::i2p::Router& router, const std::string& host,
    const std::string& op, const Bytes& body,
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax,
    const std::string& owner = {});

// One held destination for an errand that speaks to the resolver several times,
// the counterpart of federationHeldDest.
FetchTransport resolverHeldDest(bazarish::i2p::Router& router,
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax,
    const std::string& owner = {});

// The same thing for an errand that speaks to one peer several times: the
// throwaway destination is built (or taken warm) once and held for as long as
// the returned transport lives, so the tunnels and the leaseset lookup are paid
// for once instead of per call. The frame is still one request per stream - this
// changes what is dialled, not what is spoken. Unlinkability is unchanged: the
// destination is dropped with the transport, so no two errands share one, and
// the calls inside one errand are signed by the same identity anyway.
FetchTransport federationHeldDest(bazarish::i2p::Router& router,
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax,
    const std::string& owner = {});

}  // namespace bazarish::client
