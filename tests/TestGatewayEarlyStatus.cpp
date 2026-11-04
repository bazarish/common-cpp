// Bazarish project (c) 2026
#include "bazarish/GatewayProtocol.hpp"
#include "bazarish/HttpServer.hpp"
#include "bazarish/I2p.hpp"
#include "bazarish/WebSocket.hpp"

#include "TestUtil.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/3b9e1f07c2d5";
constexpr const char* kHost = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
constexpr std::chrono::seconds kQuiet{600};
constexpr std::chrono::seconds kReadyWithin{10};

void reply(const http::SocketPtr& socket, const Bytes& frame)
{
    socket->send(std::vector<unsigned char>(frame.begin(), frame.end()));
}

// A gateway whose status for a new destination comes before the answer to its create.
void answer(const http::SocketPtr& socket, const std::vector<unsigned char>& message)
{
    const Frame frame = decode(message.data(), message.size());
    if (frame.type == FrameType::eHello) {
        reply(socket, encodeJson(FrameType::eReady, frame.ref,
            {{"version", kProtocolVersion}, {"i2pd", "test"},
                {"capabilities", {{"destinationCounters", true}, {"warmPool", true}}},
                {"session", "early-status"}, {"resumed", false},
                {"endpoints", nlohmann::json::array()}, {"streams", nlohmann::json::array()}}));
        return;
    }
    if (frame.type == FrameType::eEndpointCreate) {
        reply(socket, encodeJson(FrameType::eEndpointStatus, frame.ref,
            {{"ready", true}, {"host", kHost}, {"tunnelsIn", 1}, {"tunnelsOut", 1},
                {"leaseSets", 0}, {"localRoute", false}}));
        reply(socket, encodeJson(FrameType::eOk, frame.ref, {{"host", kHost}, {"kind", "stream"}}));
    }
}

}  // namespace

int main()
{
    http::Server server(http::Server::Options{});
    http::SocketRoutes routes;
    routes.subprotocol = kSubprotocol;
    routes.admit = [](const http::Request&) -> std::optional<http::Response> { return std::nullopt; };
    routes.opened = [](const http::SocketPtr&, const http::Request&) {};
    routes.message = answer;
    routes.closed = [](const http::SocketPtr&) {};
    server.upgrade(kPath, std::move(routes));
    const int port = server.start();
    CHECK(port > 0);

    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayToken = "any";
    config.gatewayTls = false;
    config.gatewayControlMinLife = kQuiet;
    config.gatewayControlMaxLife = kQuiet;
    config.gatewayDecoyMin = kQuiet;
    config.gatewayDecoyMax = kQuiet;
    i2p::Router router(config);
    router.start();
    CHECK(router.waitReady(kReadyWithin));

    i2p::EndpointConfig wanted;
    wanted.published = false;
    const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(wanted);
    CHECK(endpoint->routingHost() == kHost);
    CHECK(endpoint->ready());

    router.stop();
    server.stop();
    return 0;
}
