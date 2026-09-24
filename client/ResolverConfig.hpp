// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <string>

namespace bazarish::client {

// The coordinate of the single central alias resolver (api/AliasResolver.md):
// the hardcoded root identity fingerprint that anchors every signed record and
// the resolver's .b32.i2p destination. Exactly two values, because the resolver
// signs and never encrypts: there is no third key to ship, and nothing here goes
// stale when the resolver rotates its signing material behind the same root.
// These are baked into the shipped client once the developer-run resolver is
// deployed;
// until then defaultResolverCoordinate() returns an unconfigured value and the
// alias path reports that resolution is unavailable. The struct stays injectable
// so the resolve logic can be exercised against a test resolver.
struct ResolverCoordinate {
    std::string rootFingerprint;  // resolver root identity fingerprint (trust anchor)
    std::string dest;             // the address the resolver answers at (blinded)

    bool configured() const { return !rootFingerprint.empty() && !dest.empty(); }
};

// The two values a build is shipped with. They are the developer-run resolver's,
// and a release replaces exactly these two lines with the deployed one's - which
// the daemon prints on its first line at start-up. Nothing else in the client
// needs changing for that, because the resolver signs rather than encrypts and
// can rotate its signing material behind the same root.
//
// These are the development resolver's. A release must not ship them.
inline constexpr const char* kResolverRootFingerprint
    = "fknq2ve6o3iuqzqu3ucllh7ozsxvsei457pe4rxsbwpm5lwdxrra";
inline constexpr const char* kResolverDest
    = "onjhiky4lshgqx3dumfbekyg7gwzfrwvvtghxdwkca6lt5slnvqkkqa5.b32.i2p";

inline ResolverCoordinate defaultResolverCoordinate()
{
    return ResolverCoordinate{kResolverRootFingerprint, kResolverDest};
}

}  // namespace bazarish::client
