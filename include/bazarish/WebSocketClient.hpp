// Bazarish project (c) 2026
#pragma once

#include "bazarish/WebSocket.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace bazarish::http {

struct SocketDial {
    std::string host;
    int port = 443;
    std::string path = "/";
    std::map<std::string, std::string> headers;
    std::string subprotocol;
    bool tls = true;
    std::chrono::seconds connectTimeout{15};
    std::chrono::seconds idleTimeout{45};
    std::size_t maxMessageBytes = 64 * 1024;
    // Zero leaves keepalive to Beast's pings at half idleTimeout.
    std::chrono::seconds pingAfterSilence{0};
    std::chrono::seconds pongTimeout{0};
    std::function<std::string()> pingPayload;
};

struct SocketDialResult {
    SocketPtr socket;
    std::string error;
};

SocketDialResult openSocket(const SocketDial& dial,
    std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message,
    std::function<void(const SocketPtr&)> closed);

struct KeptAnswer {
    bool reached = false;
    int status = 0;
    std::size_t bytes = 0;
    std::string error;
};

// One connection that asks in turn, as a browser fetches a page and what it embeds.
class KeptConnection {
public:
    explicit KeptConnection(const SocketDial& dial);
    ~KeptConnection();
    KeptConnection(const KeptConnection&) = delete;
    KeptConnection& operator=(const KeptConnection&) = delete;

    bool connected() const;
    const std::string& error() const;
    KeptAnswer get(const std::string& target, const std::map<std::string, std::string>& headers);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::http
