// Bazarish project (c) 2026
#pragma once

#include "bazarish/WebSocket.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace bazarish::http {

// Where to reach a WebSocket, and what certificate it must present.
struct SocketDial {
    std::string host;
    int port = 443;
    std::string path = "/";
    // Sent verbatim on the upgrade.
    std::map<std::string, std::string> headers;
    std::string subprotocol;
    // What travels in SNI, which need not be the host connected to: a server
    // that accepts any name lets its clients name whatever fits the cover.
    std::string sni;
    // TLS, which is what a gateway reached over a network needs. False is for
    // the hop to a front on this same machine, where the front holds the
    // certificate and the network the pin defends against is not there.
    bool tls = true;
    // Lowercase hex SHA-256 of the peer's SubjectPublicKeyInfo. Set, it is the
    // whole of the check: no chain, no name, no authority. Empty, the key is
    // learned and reported, which is a first use and not a verification - a
    // caller that stores it gets the check from then on.
    std::string pin;
    std::chrono::seconds connectTimeout{15};
    std::chrono::seconds idleTimeout{45};
    std::size_t maxMessageBytes = 64 * 1024;
};

struct SocketDialResult {
    // Null when the socket did not open; `error` says why.
    SocketPtr socket;
    // The key the peer presented, whether or not a pin was given.
    std::string pin;
    std::string error;
};

// Opens the socket and runs it on a loop of its own until it closes. The
// callbacks arrive on that loop's thread.
SocketDialResult openSocket(const SocketDial& dial,
    std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message,
    std::function<void(const SocketPtr&)> closed);

// The same certificate check without a socket: connects, shakes hands, reports
// the key and closes. What a client does to find out whether an address is a
// gateway at all before it commits to one.
struct Probe {
    bool reached = false;
    std::string pin;
    int status = 0;
    std::string error;
};
// Sends one ordinary request and reports what came back. `body` empty sends a
// GET; anything else is posted.
Probe probeHost(const SocketDial& dial, const std::string& body);

}  // namespace bazarish::http
