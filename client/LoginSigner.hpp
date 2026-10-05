// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>
#include <bazarish/Portal.hpp>

#include <string>

namespace bazarish::client {

std::string signLoginChallenge(const Identity& identity, const std::string& challenge);

class LoginSigner {
public:
    explicit LoginSigner(Identity identity);

    std::string sign(const std::string& challenge) const;

private:
    Identity identity_;
};

}  // namespace bazarish::client
