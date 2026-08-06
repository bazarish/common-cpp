// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish::service {

// Issues and verifies sign-in-with-key login challenges for one service portal.
//
// A challenge is base64(JSON {nonce, ts, aud}) bound by an HMAC tag under a
// portal-local secret, so the portal confirms - statelessly - that it issued
// the challenge, that it is fresh, and that it names this audience (this node's
// fingerprint, stopping a challenge being replayed against another server).
// Verification additionally enforces single use within the freshness window (a
// small in-memory consumed-nonce set) and checks the user's signature over the
// challenge (Portal::verifyLoginBlob), returning the signer's fingerprint.
//
// The caller passes the current time, so the component is deterministic and
// holds no clock of its own.
class LoginChallenge {
public:
    LoginChallenge(std::string secret, std::string audience, std::int64_t windowSeconds = 300);

    // A fresh challenge string to render on the login page.
    std::string issue(std::int64_t now);

    // Verifies a login: the challenge envelope (tag, freshness, audience), then
    // the user's signature over it, then single use. Returns the signer's
    // fingerprint; throws on any failure.
    std::string verify(
        const std::string& challenge, const std::string& loginBlob, std::int64_t now);

private:
    void pruneExpired(std::int64_t now);

    std::string secret_;
    std::string audience_;
    std::int64_t windowSeconds_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> consumed_;  // nonce -> ts
};

}  // namespace bazarish::service
