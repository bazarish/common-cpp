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

struct SocketDial {
    std::string host;
    int port = 443;
    std::string path = "/";
    std::map<std::string, std::string> headers;
    std::string subprotocol;
    std::string sni;
    bool tls = true;
    std::string pin;
    std::chrono::seconds connectTimeout{15};
    std::chrono::seconds idleTimeout{45};
    std::size_t maxMessageBytes = 64 * 1024;
};

struct SocketDialResult {
    SocketPtr socket;
    std::string pin;
    std::string error;
};

SocketDialResult openSocket(const SocketDial& dial,
    std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message,
    std::function<void(const SocketPtr&)> closed);

struct Probe {
    bool reached = false;
    std::string pin;
    int status = 0;
    std::string error;
};
Probe probeHost(const SocketDial& dial, const std::string& body);

}  // namespace bazarish::http
