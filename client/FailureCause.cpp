// Bazarish project (c) 2026
#include "FailureCause.hpp"

#include "Client.hpp"
#include "I2pRouter.hpp"

#include <bazarish/I2p.hpp>

namespace bazarish::client {

LinkFailure linkFailureOf(const FetchFailure failure)
{
    switch (failure) {
        case FetchFailure::eLeaseSetNotFound:
        case FetchFailure::eNotConnected:
        case FetchFailure::eBrokeAfterOpen:
            return LinkFailure::eServerUnreachable;
        case FetchFailure::eProtocol:
            return LinkFailure::eServerMalformed;
    }
    throw std::logic_error("no link failure for this fetch failure");
}

std::optional<FailureCause> carriedCause(const std::exception& error)
{
    if (dynamic_cast<const bazarish::i2p::GatewayRefusal*>(&error) != nullptr) {
        return linkCause(LinkFailure::eGatewayRefused);
    }
    if (dynamic_cast<const ProxyUnreachable*>(&error) != nullptr) {
        return linkCause(LinkFailure::eProxyUnreachable);
    }
    if (const auto* const fetch = dynamic_cast<const FetchFailed*>(&error); fetch != nullptr) {
        return linkCause(linkFailureOf(fetch->failure()));
    }
    if (const auto* const local = dynamic_cast<const LocalError*>(&error); local != nullptr) {
        return localCause(local->failure);
    }
    const auto* const link = dynamic_cast<const LinkError*>(&error);
    if (link == nullptr || link->failure == LinkFailure::eNone) {
        return std::nullopt;
    }
    return linkCause(link->failure);
}

FailureCause causeOf(const std::exception& error)
{
    if (const std::optional<FailureCause> carried = carriedCause(error); carried.has_value()) {
        return *carried;
    }
    if (dynamic_cast<const LinkError*>(&error) != nullptr) {
        return linkCause(LinkFailure::eServerRefused);
    }
    return localCause(LocalFailure::eInternal);
}

}  // namespace bazarish::client
