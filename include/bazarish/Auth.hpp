// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>

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
// Replay containment is a freshness window around the timestamp, narrowed to
// exactly-once by the ReplayCache below, which remembers each accepted
// request's signature for the duration of the window.
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

// A bounded, thread-safe replay cache that narrows replay containment from
// "anywhere inside the freshness window" to exactly-once. The classical
// signature is the natural per-request nonce: ECDSA is randomized, so two
// legitimately distinct requests never share one, while a verbatim replay
// reuses the captured signature. Only verified signatures are recorded (the
// verify overloads below consult it after both signatures check out), so a
// forged flood cannot grow the cache.
class ReplayCache {
public:
    // Records the request's classical signature and returns true if it had not
    // been seen. Returns false if this exact signature is already cached - a
    // replay. timestamp is the request's signed timestamp and now the verifier's
    // clock; entries whose timestamp has aged past the freshness window are
    // evicted, since the freshness check already rejects them.
    bool checkAndRecord(
        const Bytes& classicalSignature, std::int64_t timestamp, std::int64_t now);

private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> seen_;  // hex(sha256(sig)) -> timestamp
    std::int64_t lastSweep_ = 0;
};

// As verifyRequest / verifyRequestDigest, but additionally rejects a replay:
// once both signatures verify, the request's signature is checked against the
// cache and recorded. Throws on a replay, or on any signature / freshness
// failure like the base overloads.
std::string verifyRequest(const Headers& headers, std::int64_t now, const std::string& method,
    const std::string& path, const Bytes& body, ReplayCache& replayCache);

std::string verifyRequestDigest(const Headers& headers, std::int64_t now,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex,
    ReplayCache& replayCache);

}  // namespace bazarish::auth
