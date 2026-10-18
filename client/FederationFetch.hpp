// Bazarish project (c) 2026
#pragma once

#include "Client.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Portal.hpp>

#include <functional>
#include <optional>
#include <string>

namespace bazarish::client {

enum class FetchStage {
    eTakingDest,
    eBuildingDest,
    eReaching,
    eWaiting,
    eAskingAgain
};

void tellFetchStages(std::function<void(FetchStage)> tell);

FetchOutcome federationFetchOverI2p(bazarish::i2p::Router& router, const std::string& dest,
    const std::string& op, const Bytes& sealed,
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax,
    const std::string& owner = {});

FetchOutcome resolverFetchOverI2p(bazarish::i2p::Router& router, const std::string& host,
    const std::string& op, const Bytes& body,
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax,
    const std::string& owner = {});

// The HTTP status the site answered with; empty when the site could not be reached.
std::optional<int> postLoginOverI2p(bazarish::i2p::Router& router,
    const service::LoginCallback& callback, const std::string& challenge, const std::string& blob,
    bazarish::i2p::Privacy privacy, const std::string& owner);

FetchTransport resolverHeldDest(bazarish::i2p::Router& router,
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax,
    const std::string& owner = {});

FetchTransport federationHeldDest(bazarish::i2p::Router& router,
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax,
    const std::string& owner = {});

}  // namespace bazarish::client
