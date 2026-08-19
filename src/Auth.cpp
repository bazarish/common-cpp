// Bazarish project (c) 2026
#include "bazarish/Auth.hpp"

#include <bazarish/Hmac.hpp>

#include <openssl/crypto.h>

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <stdexcept>

namespace {

const std::string& requireHeader(const bazarish::auth::Headers& headers, const char* const name)
{
    const auto found = headers.find(name);
    if (found == headers.end()) {
        throw std::runtime_error(std::string("missing auth header: ") + name);
    }
    return found->second;
}

}  // namespace

namespace bazarish::auth {

const char* const kHeaderSession = "X-Bazarish-Session";
const char* const kHeaderSeq = "X-Bazarish-Seq";
const char* const kHeaderMac = "X-Bazarish-Mac";

const char* const kHeaderKeys = "X-Bazarish-Keys";
const char* const kHeaderTimestamp = "X-Bazarish-Timestamp";
const char* const kHeaderSignatureClassical = "X-Bazarish-Sig-Classical";
const char* const kHeaderSignaturePq = "X-Bazarish-Sig-Pq";

namespace {

// The canonical string commits to the body only through its hex SHA-256, so
// signing and verification can work from a precomputed digest without ever
// touching the raw body bytes.
std::string canonicalFromDigest(const std::int64_t timestamp, const std::string& method,
    const std::string& path, const std::string& bodySha256Hex)
{
    return "v1\n" + std::to_string(timestamp) + "\n" + method + "\n" + path + "\n" + bodySha256Hex
        + "\n";
}

}  // namespace

std::string makeCanonicalString(const std::int64_t timestamp, const std::string& method,
    const std::string& path, const Bytes& body)
{
    return canonicalFromDigest(timestamp, method, path, toHex(sha256(body)));
}

namespace {

// What the MAC covers: the same canonical string the signature covers, plus the
// sequence number, so a replay with a different counter does not verify.
std::string macCanonical(const std::int64_t timestamp, const std::string& method,
    const std::string& path, const Bytes& body, const std::uint64_t seq)
{
    return makeCanonicalString(timestamp, method, path, body) + std::to_string(seq) + "\n";
}

}  // namespace

Bytes deriveSessionKey(const Bytes& secret, const std::string& sessionId)
{
    // HKDF-like: one extraction over both halves. Neither side alone fixes the
    // key - the client brings the secret, the server the id.
    const std::string material
        = toHex(secret) + "|" + sessionId + "|bazarish session v1";
    return sha256(Bytes(material.begin(), material.end()));
}

Headers macRequest(const std::string& sessionId, const Bytes& sessionKey, const std::uint64_t seq,
    const std::int64_t timestamp, const std::string& method, const std::string& path,
    const Bytes& body)
{
    Headers headers;
    headers[kHeaderSession] = sessionId;
    headers[kHeaderSeq] = std::to_string(seq);
    headers[kHeaderTimestamp] = std::to_string(timestamp);
    headers[kHeaderMac] = bazarish::service::hmacSha256Hex(
        std::string(sessionKey.begin(), sessionKey.end()),
        macCanonical(timestamp, method, path, body, seq));
    return headers;
}

bool hasSessionHeaders(const Headers& headers)
{
    return headers.find(kHeaderSession) != headers.end()
        && headers.find(kHeaderMac) != headers.end();
}

std::uint64_t verifyMac(const Headers& headers, const Bytes& sessionKey, const std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body)
{
    const std::int64_t timestamp = std::strtoll(
        requireHeader(headers, kHeaderTimestamp).c_str(), nullptr, 10);
    if (std::llabs(now - timestamp) > kAuthFreshnessWindowSeconds) {
        throw std::runtime_error("auth timestamp outside the freshness window");
    }
    const std::uint64_t seq
        = std::strtoull(requireHeader(headers, kHeaderSeq).c_str(), nullptr, 10);
    const std::string expected = bazarish::service::hmacSha256Hex(
        std::string(sessionKey.begin(), sessionKey.end()),
        macCanonical(timestamp, method, path, body, seq));
    const std::string presented = requireHeader(headers, kHeaderMac);
    // Constant time: a MAC comparison that returns early leaks how much of it was
    // right, one byte at a time.
    if (expected.size() != presented.size()
        || CRYPTO_memcmp(expected.data(), presented.data(), expected.size()) != 0) {
        throw std::runtime_error("session MAC verification failed");
    }
    return seq;
}

Headers signRequestDigest(const Identity& identity, const std::int64_t timestamp,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex)
{
    const std::string canonical = canonicalFromDigest(timestamp, method, path, bodySha256Hex);
    const Bytes canonicalBytes(canonical.begin(), canonical.end());

    const nlohmann::json keys = {
        {"c", toBase64(identity.classical().publicDer())},
        {"pq", toBase64(identity.pq().publicDer())},
    };
    const std::string keysText = keys.dump();

    Headers headers;
    headers[kHeaderKeys] = toBase64(Bytes(keysText.begin(), keysText.end()));
    headers[kHeaderTimestamp] = std::to_string(timestamp);
    headers[kHeaderSignatureClassical] = toBase64(sign(identity.classical(), canonicalBytes));
    headers[kHeaderSignaturePq] = toBase64(sign(identity.pq(), canonicalBytes));
    return headers;
}

Headers signRequest(const Identity& identity, const std::int64_t timestamp,
    const std::string& method, const std::string& path, const Bytes& body)
{
    return signRequestDigest(identity, timestamp, method, path, toHex(sha256(body)));
}

std::string verifyRequestDigest(const Headers& headers, const std::int64_t now,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex)
{
    const std::int64_t timestamp = std::strtoll(
        requireHeader(headers, kHeaderTimestamp).c_str(), nullptr, 10);
    if (timestamp < now - kAuthFreshnessWindowSeconds
        || timestamp > now + kAuthFreshnessWindowSeconds) {
        throw std::runtime_error("auth timestamp outside the freshness window");
    }

    const Bytes keysRaw = fromBase64(requireHeader(headers, kHeaderKeys));
    const nlohmann::json keys = nlohmann::json::parse(keysRaw.begin(), keysRaw.end());
    const Bytes classicalDer = fromBase64(keys.at("c").get<std::string>());
    const Bytes pqDer = fromBase64(keys.at("pq").get<std::string>());

    const Key classical = Key::fromPublicDer(classicalDer);
    const Key pq = Key::fromPublicDer(pqDer);
    // Key-type checks close the downgrade hole, exactly as in the hybrid
    // certificate verification.
    if (!classical.isA("EC")) {
        throw std::runtime_error("auth classical key is not EC");
    }
    if (!pq.isA("ML-DSA-65")) {
        throw std::runtime_error("auth pq key is not ML-DSA-65");
    }

    const std::string canonical = canonicalFromDigest(timestamp, method, path, bodySha256Hex);
    const Bytes canonicalBytes(canonical.begin(), canonical.end());
    if (!verify(classical, canonicalBytes,
            fromBase64(requireHeader(headers, kHeaderSignatureClassical)))) {
        throw std::runtime_error("auth classical signature verification failed");
    }
    if (!verify(pq, canonicalBytes, fromBase64(requireHeader(headers, kHeaderSignaturePq)))) {
        throw std::runtime_error("auth pq signature verification failed");
    }

    return hybridFingerprint(classicalDer, pqDer);
}

std::string verifyRequest(const Headers& headers, const std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body)
{
    return verifyRequestDigest(headers, now, method, path, toHex(sha256(body)));
}

std::string authorizeRequest(const Headers& headers, const std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body,
    const std::vector<std::string>& authorizedFingerprints)
{
    const std::string caller = verifyRequest(headers, now, method, path, body);
    for (const std::string& fingerprint : authorizedFingerprints) {
        // Fingerprints are public, so a plain compare is fine; the security comes
        // from the signature already verified above.
        if (!fingerprint.empty() && fingerprint == caller) {
            return caller;
        }
    }
    throw std::runtime_error("auth caller is not an authorized operator");
}

bool ReplayCache::checkAndRecord(
    const Bytes& classicalSignature, const std::int64_t timestamp, const std::int64_t now)
{
    const std::string key = toHex(sha256(classicalSignature));
    const std::lock_guard<std::mutex> lock(mutex_);

    // Evict entries whose signed timestamp has aged out of the freshness window;
    // a replay that old is already rejected by the freshness check. Sweeping at
    // most once per second keeps eviction off the per-request hot path.
    if (now > lastSweep_) {
        const std::int64_t cutoff = now - kAuthFreshnessWindowSeconds;
        for (auto it = seen_.begin(); it != seen_.end();) {
            if (it->second < cutoff) {
                it = seen_.erase(it);
            } else {
                ++it;
            }
        }
        lastSweep_ = now;
    }

    return seen_.emplace(key, timestamp).second;
}

std::string verifyRequestDigest(const Headers& headers, const std::int64_t now,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex,
    ReplayCache& replayCache)
{
    const std::string fingerprint
        = verifyRequestDigest(headers, now, method, path, bodySha256Hex);
    // The signatures verified; enforce exactly-once on the classical signature.
    const std::int64_t timestamp
        = std::strtoll(requireHeader(headers, kHeaderTimestamp).c_str(), nullptr, 10);
    const Bytes classicalSignature = fromBase64(requireHeader(headers, kHeaderSignatureClassical));
    if (!replayCache.checkAndRecord(classicalSignature, timestamp, now)) {
        throw std::runtime_error("auth request replay detected");
    }
    return fingerprint;
}

std::string verifyRequest(const Headers& headers, const std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body, ReplayCache& replayCache)
{
    return verifyRequestDigest(headers, now, method, path, toHex(sha256(body)), replayCache);
}

}  // namespace bazarish::auth
