// Bazarish project (c) 2026
#include "GatewayAddress.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/Links.hpp>
#include <bazarish/WebSocketClient.hpp>

#include <cstdlib>
#include <stdexcept>

namespace bazarish::client {

namespace {

constexpr const char* kSecure = "https://";
constexpr int kHttpsPort = 443;
constexpr int kHighestPort = 65535;
constexpr char kQueryUnsafe[] = "&# \t\r\n";

std::string baseOf(const GatewayAddress& address)
{
    std::string text = kSecure;
    text += address.host;
    if (address.port != kHttpsPort) {
        text += ':';
        text += std::to_string(address.port);
    }
    return text + address.path;
}

}  // namespace

std::optional<GatewayAddress> GatewayAddress::parse(const std::string& text)
{
    GatewayAddress address;
    if (text.rfind(kSecure, 0) != 0) {
        return std::nullopt;
    }
    std::string rest = text.substr(std::string(kSecure).size());

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
    return baseOf(*this) + '#' + token;
}

std::optional<GatewayAddress> GatewayAddress::fromLink(const std::string& link)
{
    const std::string query = linkQuery(link, kGatewayKind);
    if (query.empty()) {
        return std::nullopt;
    }
    std::string version;
    std::string url;
    std::string token;
    std::size_t pos = 0;
    while (pos <= query.size()) {
        const std::size_t amp = query.find('&', pos);
        const std::string pair = query.substr(pos, amp == std::string::npos ? amp : amp - pos);
        const std::size_t eq = pair.find('=');
        if (eq == std::string::npos) {
            return std::nullopt;
        }
        const std::string key = pair.substr(0, eq);
        const std::string value = pair.substr(eq + 1);
        if (key == "v") {
            version = value;
        } else if (key == "url") {
            url = value;
        } else if (key == "token") {
            token = value;
        }
        if (amp == std::string::npos) {
            break;
        }
        pos = amp + 1;
    }
    if (version != kGatewayLinkVersion || url.empty() || token.empty()
        || url.find_first_of(kQueryUnsafe) != std::string::npos
        || token.find_first_of(kQueryUnsafe) != std::string::npos) {
        return std::nullopt;
    }
    return parse(url + '#' + token);
}

std::string GatewayAddress::link() const
{
    const std::string base = baseOf(*this);
    if (base.find_first_of(kQueryUnsafe) != std::string::npos
        || token.find_first_of(kQueryUnsafe) != std::string::npos) {
        throw std::invalid_argument("a gateway address with that in it does not fit a link");
    }
    return gatewayLink(base, token);
}

GatewayCheck checkGateway(const GatewayAddress& address, const std::string& pin)
{
    http::SocketDial dial;
    dial.host = address.host;
    dial.port = address.port;
    dial.path = address.path;
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
        check.error = "the gateway answered HTTP " + std::to_string(probe.status);
        return check;
    }
    check.ok = true;
    return check;
}

}  // namespace bazarish::client
