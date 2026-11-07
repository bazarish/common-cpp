// Bazarish project (c) 2026
#pragma once

#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/WebSocket.hpp>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::test {

inline constexpr const char* kFakeGatewayPath = "/3b9e1f07c2d5";
inline constexpr const char* kFakeGatewayHost
    = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";

namespace fake {

using namespace bazarish::gateway;
inline constexpr const char* kHost = kFakeGatewayHost;

inline void reply(const http::SocketPtr& socket, const Bytes& frame)
{
    socket->send(std::vector<unsigned char>(frame.begin(), frame.end()));
}

inline void answer(const http::SocketPtr& socket, const std::vector<unsigned char>& message)
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

}  // namespace fake

// A gateway whose status for a new destination comes before the answer to its create.
inline int startFakeGateway(http::Server& server)
{
    http::SocketRoutes routes;
    routes.subprotocol = gateway::kSubprotocol;
    routes.admit = [](const http::Request&) -> std::optional<http::Response> { return std::nullopt; };
    routes.opened = [](const http::SocketPtr&, const http::Request&) {};
    routes.message = fake::answer;
    routes.closed = [](const http::SocketPtr&) {};
    server.upgrade(kFakeGatewayPath, std::move(routes));
    return server.start();
}

}  // namespace bazarish::test
