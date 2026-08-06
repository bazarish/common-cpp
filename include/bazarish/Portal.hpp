// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>

#include <cstdint>
#include <string>

namespace bazarish::service {

// Sign-in-with-key wire contract - must stay in lockstep with the client
// (client-qt6 Session::signLogin). The challenge is signed as the body of a
// canonical request under this fixed method/path (so a login blob can never be
// replayed as a real API call); the four hybrid-auth headers are packed into
// base64(JSON {k,t,c,p}).
inline constexpr const char* kLoginMethod = "BZ-LOGIN";
inline constexpr const char* kLoginPath = "/portal/login";

// Verifies a login blob against the challenge it was issued for (the request
// auth freshness window contains replay) and returns the signer's fingerprint.
// Throws on any failure. The challenge's own semantics (audience, single-use,
// issuance freshness) are the portal's concern; this proves only "the holder of
// fingerprint X signed this exact challenge recently".
std::string verifyLoginBlob(const std::string& blob, std::int64_t now, const std::string& challenge);

// Produces a login blob for a given identity. The client normally does this;
// the portal keeps it for issuing/testing and to hold the format in one place.
std::string signLoginBlob(
    const Identity& identity, std::int64_t timestamp, const std::string& challenge);

}  // namespace bazarish::service
