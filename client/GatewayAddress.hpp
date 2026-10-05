// Bazarish project (c) 2026
#pragma once

#include <optional>
#include <string>

namespace bazarish::client {

struct GatewayAddress {
    std::string host;
    int port = 443;
    std::string path;
    std::string token;
    bool tls = true;

    static std::optional<GatewayAddress> parse(const std::string& text);
    std::string toString() const;
};

struct GatewayCheck {
    bool ok = false;
    std::string pin;
    std::string error;
};

GatewayCheck checkGateway(const GatewayAddress& address, const std::string& pin);

}  // namespace bazarish::client
