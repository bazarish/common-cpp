// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>
#include <bazarish/Portal.hpp>

#include <string>

namespace bazarish::client {

std::string signLoginChallenge(const Identity& identity, const std::string& challenge);

class LoginSigner {
public:
    LoginSigner(Identity identity, std::string owner);

    std::string sign(const std::string& challenge) const;

    // Signs and hands both to the challenge's callback; the HTTP status the site answered with.
    int send(const std::string& challenge) const;

private:
    Identity identity_;
    std::string owner_;
};

}  // namespace bazarish::client
