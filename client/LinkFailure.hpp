// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2pHttp.hpp>

#include <string_view>

namespace bazarish::client {

enum class LinkFailure {
    eNone,
    eNoNetwork,
    eI2pUnreachable,
    eGatewayUnreachable,
    eGatewayRefused,
    eTunnelsBuilding,
    eServerUnreachable,
    eServerDown,
    eServerRefused,
};

enum class LinkStage {
    eRouter,
    eLink,
    eTunnels,
    eDial,
    eExchange,
};

struct LinkAttempt {
    LinkStage reached = LinkStage::eRouter;
    bool viaGateway = false;
    bool gatewayReady = false;
    bool gatewayRefused = false;
    int status = 0;
};

inline bool answeredWell(const int status)
{
    constexpr int kFirstSuccess = 200;
    constexpr int kFirstNonSuccess = 300;
    return status >= kFirstSuccess && status < kFirstNonSuccess;
}

inline LinkFailure classifyLinkFailure(const bool networkDown, const LinkAttempt& attempt)
{
    if (networkDown) {
        return LinkFailure::eNoNetwork;
    }
    if (attempt.gatewayRefused) {
        return LinkFailure::eGatewayRefused;
    }
    if (attempt.status == bazarish::kI2pHttpBadGateway) {
        return LinkFailure::eServerDown;
    }
    if (attempt.status != 0) {
        return answeredWell(attempt.status) ? LinkFailure::eNone : LinkFailure::eServerRefused;
    }
    if (attempt.viaGateway && !attempt.gatewayReady) {
        return LinkFailure::eGatewayUnreachable;
    }
    switch (attempt.reached) {
        case LinkStage::eRouter:
        case LinkStage::eLink:
            return attempt.viaGateway ? LinkFailure::eGatewayUnreachable
                                      : LinkFailure::eI2pUnreachable;
        case LinkStage::eTunnels: return LinkFailure::eTunnelsBuilding;
        case LinkStage::eDial:
        case LinkStage::eExchange: return LinkFailure::eServerUnreachable;
    }
    return LinkFailure::eServerUnreachable;
}

inline std::string_view linkFailureName(const LinkFailure failure)
{
    switch (failure) {
        case LinkFailure::eNone: return "none";
        case LinkFailure::eNoNetwork: return "no network";
        case LinkFailure::eI2pUnreachable: return "the I2P network is out of reach";
        case LinkFailure::eGatewayUnreachable: return "the gateway is out of reach";
        case LinkFailure::eGatewayRefused: return "the gateway refused";
        case LinkFailure::eTunnelsBuilding: return "tunnels are being built";
        case LinkFailure::eServerUnreachable: return "the facade did not answer";
        case LinkFailure::eServerDown: return "the facade has no server behind it";
        case LinkFailure::eServerRefused: return "the server refused";
    }
    return "unknown";
}

}  // namespace bazarish::client
