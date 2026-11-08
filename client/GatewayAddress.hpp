// Bazarish project (c) 2026
#pragma once

#include <optional>
#include <string>

namespace bazarish::client {

struct GatewayAddress {
    std::string host;
    int port = 0;
    std::string path;
    bool tls = true;
    std::string fingerprint;

    static std::optional<GatewayAddress> parse(const std::string& text);
    std::string toString() const;
    // A Bazarish link of kind "gateway".
    static std::optional<GatewayAddress> fromLink(const std::string& link);
    std::string link() const;
};

struct GatewayCheck {
    bool ok = false;
    bool wrongGateway = false;
    std::string error;
};

GatewayCheck checkGateway(const GatewayAddress& address);

}  // namespace bazarish::client
