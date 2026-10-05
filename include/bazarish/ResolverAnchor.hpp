// Bazarish project (c) 2026
#pragma once

namespace bazarish {

// The alias resolver's root identity fingerprint - the trust anchor of the whole
// alias namespace, and deliberately the only copy of it. Both ends are built with
// this one value: a client verifies every record it is served against it, and the
// resolver admits only signing material that chains to it, so there is nothing
// for the two sides to disagree about. The root key itself stays on the
// air-gapped box; this is its fingerprint.
//
// Releasing a new namespace means replacing this line and kResolverDest in
// client/ResolverConfig.hpp, and nothing else.
inline constexpr const char* kResolverRootFingerprint
    = "alias3c4rsqdg7hr5vf7uqwuum3pcmdeexoongjgo35pw3rrbnnq";

}  // namespace bazarish
