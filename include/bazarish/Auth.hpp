// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <cstdint>
#include <map>
#include <string>

namespace bazarish::auth {

// Request authentication: every API request is signed with both identity
// keys (hybrid, like every identity-level statement). The server derives
// the caller's UID from the presented keys, so no prior key exchange is
// needed.
//
// Canonical string:
//   "v1\n" + timestamp + "\n" + METHOD + "\n" + path + "\n" + hex(sha256(body)) + "\n"
//
// Headers:
//   X-Bazarish-Keys          base64 of {"c": b64(EC SPKI), "pq": b64(ML-DSA SPKI)}
//   X-Bazarish-Timestamp     unix seconds
//   X-Bazarish-Sig-Classical base64, ECDSA-SHA256 over the canonical string
//   X-Bazarish-Sig-Pq        base64, ML-DSA-65 over the canonical string
//
// Replay containment is a freshness window around the timestamp; a nonce
// cache narrowing it to exactly-once is future hardening.
inline constexpr std::int64_t kAuthFreshnessWindowSeconds = 300;

extern const char* const kHeaderKeys;
extern const char* const kHeaderTimestamp;
extern const char* const kHeaderSignatureClassical;
extern const char* const kHeaderSignaturePq;

using Headers = std::map<std::string, std::string>;

std::string makeCanonicalString(std::int64_t timestamp, const std::string& method,
    const std::string& path, const Bytes& body);

// Produces the four authentication headers for a request.
Headers signRequest(const Identity& identity, std::int64_t timestamp,
    const std::string& method, const std::string& path, const Bytes& body);

// As signRequest, but the body is identified by its precomputed hex SHA-256
// (the canonical string covers only the digest, never the raw bytes). Lets a
// large request body be signed and streamed without ever holding it in memory.
Headers signRequestDigest(const Identity& identity, std::int64_t timestamp,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex);

// Verifies both signatures, both key types and the freshness window;
// returns the caller's identity fingerprint. Throws on any failure.
std::string verifyRequest(const Headers& headers, std::int64_t now, const std::string& method,
    const std::string& path, const Bytes& body);

// As verifyRequest, but against a precomputed hex SHA-256 of the body. The
// caller must compute it over the bytes it actually received (e.g. while
// streaming the body to disk) so the digest the signature commits to is the
// digest of the stored bytes.
std::string verifyRequestDigest(const Headers& headers, std::int64_t now,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex);

}  // namespace bazarish::auth
