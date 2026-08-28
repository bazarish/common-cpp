// Bazarish project (c) 2026
#pragma once

#include "Client.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include <string>

namespace bazarish::client {

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

}  // namespace bazarish::client
