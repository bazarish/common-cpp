// Bazarish project (c) 2026
#pragma once

#include <optional>
#include <string>

namespace bazarish::client {

// The one string an operator hands out, and the one thing a user pastes:
//
//     https://host[:port]/<secret path>#<token>
//
// Both halves of getting in travel together because they are useless apart: the
// path without the token is a 404, and the token without the path has nowhere
// to go. The fragment never leaves the client - it is not sent in a request
// line - so putting the token there keeps it out of anything that logs URLs.
struct GatewayAddress {
    std::string host;
    int port = 443;
    std::string path;
    std::string token;
    // False only for an http:// address, which is the hop to a front on this
    // same machine.
    bool tls = true;

    // Nothing when the text is not one of these. The caller says so plainly
    // rather than trying to make something of it.
    static std::optional<GatewayAddress> parse(const std::string& text);
    std::string toString() const;
};

// What a check of an address found. The key is what the client pins from then
// on, so a first check is a first use and every later one is a verification.
struct GatewayCheck {
    bool ok = false;
    std::string pin;
    std::string error;
};

// Sends one decoy and reports what came back. An address that answers anything
// but success is not a gateway this token opens, and the user is told so rather
// than finding out later.
GatewayCheck checkGateway(const GatewayAddress& address, const std::string& pin);

}  // namespace bazarish::client
