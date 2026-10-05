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

class Socket {
public:
    virtual ~Socket() = default;

    virtual void send(std::vector<unsigned char> message) = 0;
    virtual std::size_t pending() const = 0;
    virtual void close() = 0;
    virtual bool open() const = 0;
};

using SocketPtr = std::shared_ptr<Socket>;

struct SocketRoutes {
    std::function<std::optional<Response>(const Request&)> admit;
    std::function<void(const SocketPtr&, const Request&)> opened;
    std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message;
    std::function<void(const SocketPtr&)> closed;
    std::string subprotocol;
    std::chrono::seconds idleTimeout{45};
    std::size_t maxMessageBytes = 64 * 1024;
};

}  // namespace bazarish::http
