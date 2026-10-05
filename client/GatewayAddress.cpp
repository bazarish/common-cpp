// Bazarish project (c) 2026
#include "GatewayAddress.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/WebSocketClient.hpp>

#include <cstdlib>

namespace bazarish::client {

namespace {

constexpr const char* kSecure = "https://";
constexpr const char* kPlain = "http://";
constexpr int kHttpsPort = 443;
constexpr int kHttpPort = 80;
constexpr int kHighestPort = 65535;

}  // namespace

std::optional<GatewayAddress> GatewayAddress::parse(const std::string& text)
{
    GatewayAddress address;
    std::string rest;
    if (text.rfind(kSecure, 0) == 0) {
        rest = text.substr(std::string(kSecure).size());
        address.port = kHttpsPort;
    } else if (text.rfind(kPlain, 0) == 0) {
        rest = text.substr(std::string(kPlain).size());
        address.tls = false;
        address.port = kHttpPort;
    } else {
        return std::nullopt;
    }

    const std::size_t hash = rest.find('#');
    if (hash == std::string::npos) {
        return std::nullopt;
    }
    address.token = rest.substr(hash + 1);
    rest = rest.substr(0, hash);
    if (address.token.empty()) {
        return std::nullopt;
    }

    const std::size_t slash = rest.find('/');
    if (slash == std::string::npos) {
        return std::nullopt;
    }
    address.path = rest.substr(slash);
    std::string authority = rest.substr(0, slash);
    if (address.path.size() < 2 || authority.empty()) {
        return std::nullopt;
    }

    const std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        const std::string number = authority.substr(colon + 1);
        if (number.empty() || number.find_first_not_of("0123456789") != std::string::npos) {
            return std::nullopt;
        }
        const long port = std::strtol(number.c_str(), nullptr, 10);
        if (port <= 0 || port > kHighestPort) {
            return std::nullopt;
        }
        address.port = static_cast<int>(port);
        authority = authority.substr(0, colon);
    }
    if (authority.empty()) {
        return std::nullopt;
    }
    address.host = authority;
    return address;
}

std::string GatewayAddress::toString() const
{
    std::string text = tls ? kSecure : kPlain;
    text += host;
    const int standard = tls ? kHttpsPort : kHttpPort;
    if (port != standard) {
        text += ':';
        text += std::to_string(port);
    }
    text += path;
    text += '#';
    text += token;
    return text;
}

GatewayCheck checkGateway(const GatewayAddress& address, const std::string& pin)
{
    http::SocketDial dial;
    dial.host = address.host;
    dial.port = address.port;
    dial.path = address.path;
    dial.tls = address.tls;
    dial.pin = pin;
    dial.headers[gateway::kTokenHeader] = address.token;

    const Bytes noise = randomBytes(gateway::kDecoyRequestMinBytes);
    const http::Probe probe
        = http::probeHost(dial, std::string(noise.begin(), noise.end()));

    GatewayCheck check;
    check.pin = probe.pin;
    if (!probe.reached) {
        check.error = probe.error;
        return check;
    }
    if (probe.status != 200) {
        check.error = "that address and token open nothing here";
        return check;
    }
    check.ok = true;
    return check;
}

}  // namespace bazarish::client
