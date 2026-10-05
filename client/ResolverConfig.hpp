// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/ResolverAnchor.hpp>

#include <string>

namespace bazarish::client {

// The coordinate of the single central alias resolver (api/FederatedResolve.md):
// the hardcoded root identity fingerprint that anchors every signed record and
// the resolver's .b32.i2p destination. Exactly two values, because the resolver
// signs and never encrypts: there is no third key to ship, and nothing here goes
// stale when the resolver rotates its signing material behind the same root.
// Both are baked into the shipped client; a coordinate with either half empty
// leaves the alias path reporting that resolution is unavailable. The struct
// stays injectable so the resolve logic can be exercised against a test
// resolver.
struct ResolverCoordinate {
    std::string rootFingerprint;  // resolver root identity fingerprint (trust anchor)
    std::string dest;             // the address the resolver answers at

    bool configured() const { return !rootFingerprint.empty() && !dest.empty(); }
};

// The address a build is shipped with: the i2pd server tunnel the deployed
// daemon answers behind. The root fingerprint that anchors it is not repeated
// here - it is bazarish::kResolverRootFingerprint, the same constant the resolver
// is built with. Nothing else in the client needs changing when the resolver
// rotates its signing material, because that happens behind the same root.
//
// A test or a differently-pointed client is handed its coordinate through
// Session::setResolverCoordinate; there is no ambient second way in.
inline constexpr const char* kResolverDest
    = "alias3huye47ahu2as5grktyc75w5wqr45elavek52t72vcooy3a.b32.i2p";

inline ResolverCoordinate defaultResolverCoordinate()
{
    return ResolverCoordinate{bazarish::kResolverRootFingerprint, kResolverDest};
}

}  // namespace bazarish::client
