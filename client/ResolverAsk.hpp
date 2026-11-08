// Bazarish project (c) 2026
#pragma once

#include "Client.hpp"
#include "ResolverConfig.hpp"

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <string>

namespace bazarish::client {

inline constexpr char kChannelOp[] = "channel";
inline constexpr char kSealedOp[] = "sealed";

// One request through the resolver's sealed channel. The checked channel key is held per
// resolver until the resolver answers that it no longer knows it; then it is fetched anew once.
FetchOutcome askResolver(const ResolverCoordinate& resolver, const FetchTransport& transport,
    const std::string& op, const Bytes& body, std::int64_t now);

}  // namespace bazarish::client
