// Bazarish project (c) 2026
#include "GatewayAddress.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/GatewayChannel.hpp>
#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/Links.hpp>
#include <bazarish/WebSocketClient.hpp>

#include <boost/asio/ip/address.hpp>

#include <condition_variable>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <stdexcept>

namespace bazarish::client {

namespace {

constexpr const char* kSecure = "https://";
constexpr const char* kPlain = "http://";
constexpr int kHttpsPort = 443;
constexpr int kHttpPort = 80;
constexpr int kHighestPort = 65535;
constexpr char kQueryUnsafe[] = "&# \t\r\n";
constexpr char kDigits[] = "0123456789";

int standardPort(const bool tls)
{
    return tls ? kHttpsPort : kHttpPort;
}

bool isIpv6(const std::string& host)
{
    boost::system::error_code error;
    const boost::asio::ip::address address = boost::asio::ip::make_address(host, error);
    return !error && address.is_v6();
}

std::string baseOf(const GatewayAddress& address)
{
    std::string text = address.tls ? kSecure : kPlain;
    text += isIpv6(address.host) ? "[" + address.host + "]" : address.host;
    if (address.port != standardPort(address.tls)) {
        text += ':';
        text += std::to_string(address.port);
    }
    return text + address.path;
}

std::optional<int> portOf(const std::string& number)
{
    if (number.empty() || number.find_first_not_of(kDigits) != std::string::npos) {
        return std::nullopt;
    }
    const long port = std::strtol(number.c_str(), nullptr, 10);
    if (port <= 0 || port > kHighestPort) {
        return std::nullopt;
    }
    return static_cast<int>(port);
}

}  // namespace

std::optional<GatewayAddress> GatewayAddress::parse(const std::string& text)
{
    GatewayAddress address;
    std::string rest;
    if (text.rfind(kSecure, 0) == 0) {
        rest = text.substr(std::string(kSecure).size());
    } else if (text.rfind(kPlain, 0) == 0) {
        address.tls = false;
        rest = text.substr(std::string(kPlain).size());
    } else {
        return std::nullopt;
    }
    address.port = standardPort(address.tls);

    const std::size_t hash = rest.find('#');
    if (hash == std::string::npos) {
        return std::nullopt;
    }
    address.fingerprint = rest.substr(hash + 1);
    rest = rest.substr(0, hash);
    if (!isFingerprint(address.fingerprint)) {
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

    if (authority.front() == '[') {
        const std::size_t close = authority.find(']');
        if (close == std::string::npos) {
            return std::nullopt;
        }
        address.host = authority.substr(1, close - 1);
        const std::string after = authority.substr(close + 1);
        if (!isIpv6(address.host)) {
            return std::nullopt;
        }
        if (!after.empty()) {
            if (after.front() != ':') {
                return std::nullopt;
            }
            const std::optional<int> port = portOf(after.substr(1));
            if (!port.has_value()) {
                return std::nullopt;
            }
            address.port = *port;
        }
        return address;
    }

    const std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        const std::optional<int> port = portOf(authority.substr(colon + 1));
        if (!port.has_value()) {
            return std::nullopt;
        }
        address.port = *port;
        authority = authority.substr(0, colon);
    }
    if (authority.empty() || authority.find(':') != std::string::npos) {
        return std::nullopt;
    }
    address.host = authority;
    return address;
}

std::string GatewayAddress::toString() const
{
    return baseOf(*this) + '#' + fingerprint;
}

std::optional<GatewayAddress> GatewayAddress::fromLink(const std::string& link)
{
    const std::string query = linkQuery(link, kGatewayKind);
    if (query.empty()) {
        return std::nullopt;
    }
    std::string version;
    std::string url;
    std::string fingerprint;
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
        } else if (key == "fp") {
            fingerprint = value;
        }
        if (amp == std::string::npos) {
            break;
        }
        pos = amp + 1;
    }
    if (version != kGatewayLinkVersion || url.empty()
        || url.find_first_of(kQueryUnsafe) != std::string::npos) {
        return std::nullopt;
    }
    return parse(url + '#' + fingerprint);
}

std::string GatewayAddress::link() const
{
    const std::string base = baseOf(*this);
    if (base.find_first_of(kQueryUnsafe) != std::string::npos) {
        throw std::invalid_argument("a gateway address with that in it does not fit a link");
    }
    return gatewayLink(base, fingerprint);
}

GatewayCheck checkGateway(const GatewayAddress& address)
{
    http::SocketDial dial;
    dial.host = address.host;
    dial.port = address.port;
    dial.path = address.path;
    dial.tls = address.tls;
    dial.maxMessageBytes = gateway::kMaxRecordBytes;

    struct FirstMessage {
        std::mutex mutex;
        std::condition_variable arrived;
        std::optional<Bytes> card;
        bool closed = false;
    };
    const std::shared_ptr<FirstMessage> first = std::make_shared<FirstMessage>();
    const http::SocketDialResult opened = http::openSocket(
        dial,
        [first](const http::SocketPtr&, const std::vector<unsigned char>& message) {
            const std::lock_guard<std::mutex> lock(first->mutex);
            if (!first->card.has_value()) {
                first->card = Bytes(message.begin(), message.end());
            }
            first->arrived.notify_all();
        },
        [first](const http::SocketPtr&) {
            const std::lock_guard<std::mutex> lock(first->mutex);
            first->closed = true;
            first->arrived.notify_all();
        });
    GatewayCheck check;
    if (opened.socket == nullptr) {
        check.error = opened.error;
        return check;
    }
    std::optional<Bytes> card;
    {
        std::unique_lock<std::mutex> lock(first->mutex);
        (void)first->arrived.wait_for(lock, gateway::kHandshakeTimeout,
            [&first]() { return first->card.has_value() || first->closed; });
        card = first->card;
    }
    opened.socket->close();
    if (!card.has_value()) {
        check.error = "the gateway sent no card";
        return check;
    }
    const std::optional<Bytes> uncovered = gateway::Cover(address.fingerprint).open(*card);
    if (!uncovered.has_value()) {
        check.wrongGateway = true;
        check.error = "the gateway's card is not sealed for this link";
        return check;
    }
    try {
        (void)gateway::cardSealingKey(gateway::unpadded(*uncovered), address.fingerprint);
    } catch (const gateway::WrongGateway& error) {
        check.wrongGateway = true;
        check.error = error.what();
        return check;
    } catch (const std::exception& error) {
        check.error = std::string("the gateway's card does not read: ") + error.what();
        return check;
    }
    check.ok = true;
    return check;
}

}  // namespace bazarish::client
