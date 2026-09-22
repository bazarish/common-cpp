// Bazarish project (c) 2026
#pragma once

#include "bazarish/HttpServer.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::http {

// A WebSocket, after the upgrade. It rides the same listener, the same parser
// and the same limits as every other request this server serves: a second
// stack in one binary is two parsers, two limits and two places for a bug to
// hide.
//
// Binary messages only. A text frame is not a mistake to be tolerated - a
// caller that sends one is not speaking the protocol - and it closes the socket.
class Socket {
public:
    virtual ~Socket() = default;

    // Queues one binary message. Callable from any thread; messages leave in
    // the order they were queued, one at a time.
    virtual void send(std::vector<unsigned char> message) = 0;
    // Queued bytes that have not reached the kernel yet. A writer keeps its own
    // queue bounded by this, and a writer with something urgent holds back what
    // is not until this falls.
    virtual std::size_t pending() const = 0;
    virtual void close() = 0;
    virtual bool open() const = 0;
};

using SocketPtr = std::shared_ptr<Socket>;

struct SocketRoutes {
    // Runs before the upgrade, on the ordinary request. Returning a response
    // refuses the upgrade and sends that response instead, which is how an
    // unauthorised upgrade becomes the same 404 as everything else on the host.
    std::function<std::optional<Response>(const Request&)> admit;
    // The upgrade succeeded. The request is the one that carried it, so a
    // handler reads its headers here and nowhere later.
    std::function<void(const SocketPtr&, const Request&)> opened;
    std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message;
    // The socket is gone, however it went. Called once.
    std::function<void(const SocketPtr&)> closed;
    // A socket that says nothing for this long is pinged, and dropped if the
    // ping goes unanswered. A peer that has stopped answering is not a peer
    // whose session should be held open for it.
    // Echoed back on the upgrade when set, so a client that names the protocol
    // it speaks is told the server speaks it too.
    std::string subprotocol;
    std::chrono::seconds idleTimeout{45};
    std::size_t maxMessageBytes = 64 * 1024;
};

}  // namespace bazarish::http
