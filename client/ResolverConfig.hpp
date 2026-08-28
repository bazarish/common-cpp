// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <string>

namespace bazarish::client {

// The coordinate of the single central alias resolver (api/AliasResolver.md):
// the hardcoded root identity fingerprint that anchors every signed record, the
// resolver's .b32.i2p serving destination, and its serving sealing key. These
// are baked into the shipped client once the developer-run resolver is deployed;
// until then defaultResolverCoordinate() returns an unconfigured value and the
// alias path reports that resolution is unavailable. The struct stays injectable
// so the resolve logic can be exercised against a test resolver.
struct ResolverCoordinate {
    std::string rootFingerprint;  // resolver root identity fingerprint (trust anchor)
    std::string dest;             // resolver's .b32.i2p serving destination
    Bytes sealingKeyDer;          // resolver's serving sealing key (SPKI DER)

    bool configured() const
    {
        return !rootFingerprint.empty() && !dest.empty() && !sealingKeyDer.empty();
    }
};

// The compiled-in resolver coordinate. Empty until the developer-run resolver's
// address and keys are baked in (a deliberate placeholder, not a default route).
inline ResolverCoordinate defaultResolverCoordinate()
{
    return ResolverCoordinate{};
}

}  // namespace bazarish::client
