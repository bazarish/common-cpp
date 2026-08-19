// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

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

// --- Session authentication ---
//
// The hybrid signature above is ~8.3 KB and an ML-DSA verification per request,
// which is a lot to spend on "this is still me". A client presents it once to
// open a session, then authenticates each request with an HMAC over the same
// canonical string. Beyond size, this is what the server ends up holding: a
// signature is evidence to a third party that this user made this request; a MAC
// is not, because the server could have produced it itself.
//
// Session headers (in place of the four above):
//   X-Bazarish-Session   the handle for this request, hex
//   X-Bazarish-Seq       per-session request counter, strictly increasing
//   X-Bazarish-Mac       base64 HMAC-SHA256 over "<canonical string>" + seq + "\n"
//
// The handle is derived per request, not a fixed id: a facade sits in the middle
// of every call, and a constant identifier would hand it a way to tie a user's
// requests together for the life of the session. Each request carries a
// different one, and only the server that holds the secret can tell they belong
// together.
//
// The secret is sealed to a hybrid key on the way in, and the server's answer is
// sealed to a one-time key the client puts inside that envelope - so the facade
// sees an opaque blob in each direction and never learns the secret the handles
// and the MAC key come from. HMAC-SHA256 itself needs no such care.
extern const char* const kHeaderSession;
extern const char* const kHeaderSeq;
extern const char* const kHeaderMac;

// Session lifetime, chosen at random inside this window per session: a fixed
// lifetime makes every client's renewal predictable and simultaneous, and the
// point of a short-lived key is that a leaked one is worth little.
inline constexpr std::int64_t kSessionMinLifetimeSeconds = 3600;
inline constexpr std::int64_t kSessionMaxLifetimeSeconds = 7200;

// Derives the per-session MAC key from the secret the client sealed and the id
// the server assigned, so neither side alone fixes it.
Bytes deriveSessionKey(const Bytes& secret, const std::string& sessionId);

// The handle a given request carries. Unpredictable without the secret, so a
// facade cannot link two requests of the same session, and the server can index
// the handles it expects next.
std::string sessionHandle(const Bytes& secret, std::uint64_t seq);

// The three session headers for a request. `seq` must be higher than any seq
// this session has used before.
Headers macRequest(const std::string& handle, const Bytes& sessionKey, std::uint64_t seq,
    std::int64_t timestamp, const std::string& method, const std::string& path, const Bytes& body);

// Verifies the MAC of a request against a session key, returning the sequence
// number it carried. Throws when a header is missing, the MAC does not match, or
// the timestamp is outside the freshness window - the caller checks the sequence
// against what this session has already used.
std::uint64_t verifyMac(const Headers& headers, const Bytes& sessionKey, std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body);

// True when a request presents session headers at all (so the verifier knows
// which of the two schemes to apply).
bool hasSessionHeaders(const Headers& headers);


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

// Verifies the request signature like verifyRequest, then requires the recovered
// caller fingerprint to be one of the authorized fingerprints. Returns the caller
// fingerprint. Throws on a bad signature, a stale request, or an unauthorized
// caller. An empty authorized list authorizes nobody. This is the gate for
// operator-internal endpoints (no shared secret): the caller proves possession of
// an authorized identity by signing the request, exactly like every other
// identity statement in the system.
std::string authorizeRequest(const Headers& headers, std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body,
    const std::vector<std::string>& authorizedFingerprints);

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
