// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>
#include <bazarish/Portal.hpp>

#include <string>

namespace bazarish::client {

// Signs sign-in-with-key challenges with one account's identity.
//
// Signing is local work: a key, a challenge, no server. It lives in an object of
// its own so a front-end can do it on the thread the user clicked on rather than
// queueing it behind whatever that account's worker is in the middle of - a sync
// over I2P can take a minute, and a signature that arrives a minute after the
// click is one nobody is still waiting for.
//
// The identity here is a copy of its own (built from a PEM round trip), so the
// two never touch the same key object from two threads.
// Fails closed: a challenge that will not say who consumes the signature is not
// signed at all, because the user would have nothing on screen to compare with
// the site they think they are signing in to.
std::string signLoginChallenge(const Identity& identity, const std::string& challenge);

class LoginSigner {
public:
    explicit LoginSigner(Identity identity);

    std::string sign(const std::string& challenge) const;

private:
    Identity identity_;
};

}  // namespace bazarish::client
