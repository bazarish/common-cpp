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
const char* const kHeaderNonce = "X-Bazarish-Nonce";

namespace {

std::string canonicalFromDigest(const std::int64_t timestamp, const std::string& method,
    const std::string& path, const std::string& bodySha256Hex, const std::string& clientId)
{
    const std::string base = "v2\n" + std::to_string(timestamp) + "\n" + method + "\n" + path
        + "\n" + bodySha256Hex + "\n";
    return clientId.empty() ? base : base + clientId + "\n";
}

}  // namespace

std::string makeCanonicalString(const std::int64_t timestamp, const std::string& method,
    const std::string& path, const Bytes& body, const std::string& clientId)
{
    return canonicalFromDigest(timestamp, method, path, toHex(sha256(body)), clientId);
}

namespace {

std::string signatureCanonical(const std::int64_t timestamp, const std::string& method,
    const std::string& path, const std::string& bodySha256Hex, const std::string& clientId,
    const std::string& nonce)
{
    return canonicalFromDigest(timestamp, method, path, bodySha256Hex, clientId) + nonce + "\n";
}

std::string macCanonical(const std::int64_t timestamp, const std::string& method,
    const std::string& path, const Bytes& body, const std::uint64_t seq,
    const std::string& clientId)
{
    return makeCanonicalString(timestamp, method, path, body, clientId) + std::to_string(seq)
        + "\n";
}

}  // namespace

Bytes deriveSessionKey(const Bytes& secret, const std::string& sessionId)
{
    const std::string material
        = toHex(secret) + "|" + sessionId + "|bazarish session v1";
    return sha256(Bytes(material.begin(), material.end()));
}

std::string sessionHandle(const Bytes& secret, const std::uint64_t seq)
{
    return bazarish::service::hmacSha256Hex(
        std::string(secret.begin(), secret.end()), "handle|" + std::to_string(seq));
}

Headers macRequest(const std::string& handle, const Bytes& sessionKey, const std::uint64_t seq,
    const std::int64_t timestamp, const std::string& method, const std::string& path,
    const Bytes& body, const std::string& clientId)
{
    Headers headers;
    headers[kHeaderSession] = handle;
    headers[kHeaderSeq] = std::to_string(seq);
    headers[kHeaderTimestamp] = std::to_string(timestamp);
    headers[kHeaderMac] = bazarish::service::hmacSha256Hex(
        std::string(sessionKey.begin(), sessionKey.end()),
        macCanonical(timestamp, method, path, body, seq, clientId));
    return headers;
}

bool hasSessionHeaders(const Headers& headers)
{
    return headers.find(kHeaderSession) != headers.end()
        && headers.find(kHeaderMac) != headers.end();
}

std::uint64_t verifyMac(const Headers& headers, const Bytes& sessionKey, const std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body,
    const std::string& clientId)
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
        macCanonical(timestamp, method, path, body, seq, clientId));
    const std::string presented = requireHeader(headers, kHeaderMac);
    if (expected.size() != presented.size()
        || CRYPTO_memcmp(expected.data(), presented.data(), expected.size()) != 0) {
        throw std::runtime_error("session MAC verification failed");
    }
    return seq;
}

Headers signRequestDigest(const Identity& identity, const std::int64_t timestamp,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex,
    const std::string& clientId)
{
    const std::string nonce = toBase64(randomBytes(kAuthNonceBytes));
    const std::string canonical
        = signatureCanonical(timestamp, method, path, bodySha256Hex, clientId, nonce);
    const Bytes canonicalBytes(canonical.begin(), canonical.end());

    const nlohmann::json keys = {
        {"c", toBase64(identity.classical().publicDer())},
        {"pq", toBase64(identity.pq().publicDer())},
    };
    const std::string keysText = keys.dump();

    Headers headers;
    headers[kHeaderKeys] = toBase64(Bytes(keysText.begin(), keysText.end()));
    headers[kHeaderTimestamp] = std::to_string(timestamp);
    headers[kHeaderNonce] = nonce;
    headers[kHeaderSignatureClassical] = toBase64(sign(identity.classical(), canonicalBytes));
    headers[kHeaderSignaturePq] = toBase64(sign(identity.pq(), canonicalBytes));
    return headers;
}

Headers signRequest(const Identity& identity, const std::int64_t timestamp,
    const std::string& method, const std::string& path, const Bytes& body,
    const std::string& clientId)
{
    return signRequestDigest(identity, timestamp, method, path, toHex(sha256(body)), clientId);
}

std::string verifyRequestDigest(const Headers& headers, const std::int64_t now,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex,
    const std::string& clientId)
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
    if (!classical.isA(kClassicalSigningAlgorithm)) {
        throw std::runtime_error("auth classical key is not Ed25519");
    }
    if (!pq.isA(kPqSigningAlgorithm)) {
        throw std::runtime_error("auth pq key is not ML-DSA-65");
    }

    const std::string canonical = signatureCanonical(
        timestamp, method, path, bodySha256Hex, clientId, requireHeader(headers, kHeaderNonce));
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
    const std::string& method, const std::string& path, const Bytes& body,
    const std::string& clientId)
{
    return verifyRequestDigest(headers, now, method, path, toHex(sha256(body)), clientId);
}

std::string authorizeRequest(const Headers& headers, const std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body,
    const std::vector<std::string>& authorizedFingerprints, ReplayCache& replayCache)
{
    const std::string caller = verifyRequest(headers, now, method, path, body);
    for (const std::string& fingerprint : authorizedFingerprints) {
        if (!fingerprint.empty() && fingerprint == caller) {
            const std::int64_t timestamp
                = std::strtoll(requireHeader(headers, kHeaderTimestamp).c_str(), nullptr, 10);
            if (!replayCache.checkAndRecord(
                    requireHeader(headers, kHeaderNonce), timestamp, now)) {
                throw std::runtime_error("auth request replay detected");
            }
            return caller;
        }
    }
    throw std::runtime_error("auth caller is not an authorized operator");
}

bool ReplayCache::checkAndRecord(
    const std::string& nonce, const std::int64_t timestamp, const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);

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

    return seen_.emplace(nonce, timestamp).second;
}

std::string verifyRequestDigest(const Headers& headers, const std::int64_t now,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex,
    ReplayCache& replayCache, const std::string& clientId)
{
    const std::string fingerprint
        = verifyRequestDigest(headers, now, method, path, bodySha256Hex, clientId);
    const std::int64_t timestamp
        = std::strtoll(requireHeader(headers, kHeaderTimestamp).c_str(), nullptr, 10);
    if (!replayCache.checkAndRecord(requireHeader(headers, kHeaderNonce), timestamp, now)) {
        throw std::runtime_error("auth request replay detected");
    }
    return fingerprint;
}

std::string verifyRequest(const Headers& headers, const std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body,
    ReplayCache& replayCache, const std::string& clientId)
{
    return verifyRequestDigest(
        headers, now, method, path, toHex(sha256(body)), replayCache, clientId);
}

}  // namespace bazarish::auth
