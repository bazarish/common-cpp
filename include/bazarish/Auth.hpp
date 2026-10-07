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

inline constexpr std::int64_t kAuthFreshnessWindowSeconds = 300;

extern const char* const kHeaderKeys;
extern const char* const kHeaderTimestamp;
extern const char* const kHeaderSignatureClassical;
extern const char* const kHeaderSignaturePq;
extern const char* const kHeaderNonce;

// Ed25519 is deterministic, so a retry of the same request would otherwise be
// indistinguishable from its replay: the nonce is what makes it distinct.
inline constexpr std::size_t kAuthNonceBytes = 16;

using Headers = std::map<std::string, std::string>;

extern const char* const kHeaderSession;
extern const char* const kHeaderSeq;
extern const char* const kHeaderMac;

inline constexpr std::int64_t kSessionMinLifetimeSeconds = 3600;
inline constexpr std::int64_t kSessionMaxLifetimeSeconds = 7200;

Bytes deriveSessionKey(const Bytes& secret, const std::string& sessionId);

std::string sessionHandle(const Bytes& secret, std::uint64_t seq);

Headers macRequest(const std::string& handle, const Bytes& sessionKey, std::uint64_t seq,
    std::int64_t timestamp, const std::string& method, const std::string& path, const Bytes& body,
    const std::string& clientId = {});

std::uint64_t verifyMac(const Headers& headers, const Bytes& sessionKey, std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body,
    const std::string& clientId = {});

bool hasSessionHeaders(const Headers& headers);

std::string makeCanonicalString(std::int64_t timestamp, const std::string& method,
    const std::string& path, const Bytes& body, const std::string& clientId = {});

Headers signRequest(const Identity& identity, std::int64_t timestamp,
    const std::string& method, const std::string& path, const Bytes& body,
    const std::string& clientId = {});

Headers signRequestDigest(const Identity& identity, std::int64_t timestamp,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex,
    const std::string& clientId = {});

std::string verifyRequest(const Headers& headers, std::int64_t now, const std::string& method,
    const std::string& path, const Bytes& body, const std::string& clientId = {});

std::string verifyRequestDigest(const Headers& headers, std::int64_t now,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex,
    const std::string& clientId = {});

std::string authorizeRequest(const Headers& headers, std::int64_t now,
    const std::string& method, const std::string& path, const Bytes& body,
    const std::vector<std::string>& authorizedFingerprints);

class ReplayCache {
public:
    bool checkAndRecord(const std::string& nonce, std::int64_t timestamp, std::int64_t now);

private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> seen_;
    std::int64_t lastSweep_ = 0;
};

std::string verifyRequest(const Headers& headers, std::int64_t now, const std::string& method,
    const std::string& path, const Bytes& body, ReplayCache& replayCache,
    const std::string& clientId = {});

std::string verifyRequestDigest(const Headers& headers, std::int64_t now,
    const std::string& method, const std::string& path, const std::string& bodySha256Hex,
    ReplayCache& replayCache, const std::string& clientId = {});

}  // namespace bazarish::auth
