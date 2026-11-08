// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/ResolverAnchor.hpp>

#include <string>

namespace bazarish::client {

struct ResolverCoordinate {
    std::string rootFingerprint;
    std::string dest;

    bool configured() const { return !rootFingerprint.empty() && !dest.empty(); }
};

// The i2pd server tunnel the deployed daemon answers behind.
inline constexpr const char* kResolverDest
    = "alias3huye47ahu2as5grktyc75w5wqr45elavek52t72vcooy3a.b32.i2p";

inline constexpr const char* kRegistryBotAlias = "alias";
inline constexpr const char* kRegistrySite = "https://alias.bazarish.org";
inline constexpr const char* kRegistrySiteI2p
    = "http://bazarokjfvwogh3l4htrtalocpi45um2hewxmh5sn72sxyucvxdq.b32.i2p";

inline ResolverCoordinate defaultResolverCoordinate()
{
    return ResolverCoordinate{bazarish::kResolverRootFingerprint, kResolverDest};
}

}  // namespace bazarish::client
