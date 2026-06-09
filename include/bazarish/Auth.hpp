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

// Verifies both signatures, both key types and the freshness window;
// returns the caller's identity fingerprint. Throws on any failure.
std::string verifyRequest(const Headers& headers, std::int64_t now, const std::string& method,
    const std::string& path, const Bytes& body);

}  // namespace bazarish::auth
