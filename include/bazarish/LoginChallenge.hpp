// Bazarish project (c) 2026
#pragma once

#include <bazarish/Portal.hpp>

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish::service {

// Issues and verifies sign-in-with-key login challenges for one service portal.
//
// A challenge is base64(JSON {v, nonce, ts, consumer, tag}) bound by an HMAC tag
// under a portal-local secret, so the portal confirms - statelessly - that it
// issued the challenge, that it is fresh, and that it names this consumer (this
// deployment, named the way its users see it, stopping a challenge being
// replayed against another portal). The tag covers the consumer, so a captured
// challenge cannot be re-labelled and shown to a user as somewhere else.
// Verification additionally enforces single use within the freshness window (a
// small in-memory consumed-nonce set) and checks the user's signature over the
// challenge (Portal::verifyLoginBlob), returning the signer's fingerprint.
//
// The caller passes the current time, so the component is deterministic and
// holds no clock of its own.
class LoginChallenge {
public:
    // Throws when the consumer is incomplete: a portal that will not say who it
    // is has no business asking anyone to sign for it.
    LoginChallenge(std::string secret, LoginConsumer consumer, std::int64_t windowSeconds = 300);

    // A fresh challenge string to render on the login page.
    std::string issue(std::int64_t now);

    // Verifies a login: the challenge envelope (version, consumer, freshness,
    // tag), then the user's signature over it, then single use. Returns the
    // signer's fingerprint; throws on any failure.
    std::string verify(
        const std::string& challenge, const std::string& loginBlob, std::int64_t now);

    // The words this portal currently signs under, and the operator's way to
    // change them while it runs. A challenge handed out before the change names
    // the old consumer and stops verifying: it was shown to a user under words
    // this portal no longer stands behind, and re-labelling it is exactly what
    // the tag exists to prevent. Throws when the new consumer is incomplete.
    LoginConsumer consumer() const;
    void setConsumer(LoginConsumer consumer);

private:
    void pruneExpired(std::int64_t now);
    std::string currentCanonical() const;

    std::string secret_;
    LoginConsumer consumer_;
    std::string canonicalConsumer_;
    std::int64_t windowSeconds_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> consumed_;  // nonce -> ts
};

}  // namespace bazarish::service
