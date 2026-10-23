// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>
#include <bazarish/Portal.hpp>

#include <optional>
#include <string>

namespace bazarish::client {

std::string signLoginChallenge(const Identity& identity, const std::string& challenge);

class LoginSigner {
public:
    LoginSigner(Identity identity, std::string owner);

    std::string sign(const std::string& challenge) const;

    // Signs and hands both to the challenge's callback; the HTTP status, empty if unreached.
    std::optional<int> send(const std::string& challenge) const;

    // The challenge a link points at, checked to return where it came from; empty if unreached.
    std::optional<std::string> fetch(const std::string& link) const;

private:
    Identity identity_;
    std::string owner_;
};

}  // namespace bazarish::client
