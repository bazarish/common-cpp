// Bazarish project (c) 2026
#include "bazarish/Auth.hpp"

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

}  // namespace bazarish::auth
