// Bazarish project (c) 2026
#include "LoginSigner.hpp"

#include "FederationFetch.hpp"
#include "I2pRouter.hpp"

#include <bazarish/Log.hpp>

#include <ctime>
#include <stdexcept>
#include <utility>

namespace bazarish::client {

LoginSigner::LoginSigner(Identity identity, std::string owner)
    : identity_(std::move(identity))
    , owner_(std::move(owner))
{
}

std::string signLoginChallenge(const Identity& identity, const std::string& challenge)
{
    const service::LoginConsumer consumer = service::readLoginConsumer(challenge);
    const std::optional<service::LoginCallback> callback = service::readLoginCallback(challenge);
    std::string places;
    for (const std::string& place : consumer.place) {
        places += places.empty() ? place : ", " + place;
    }
    log::info("signing a login for \"{}\" at {} as {}{}", consumer.name, places,
        consumer.role, callback ? ", to be sent to " + log::redact(callback->host) : "");
    return service::signLoginBlob(
        identity, static_cast<std::int64_t>(std::time(nullptr)), challenge);
}

std::string LoginSigner::sign(const std::string& challenge) const
{
    return signLoginChallenge(identity_, challenge);
}

std::optional<int> LoginSigner::send(const std::string& challenge) const
{
    const std::optional<service::LoginCallback> callback = service::readLoginCallback(challenge);
    if (!callback) {
        throw std::runtime_error("this challenge names no address to send the signature to");
    }
    bazarish::i2p::Router* const router = sharedI2pRouterIfRunning();
    if (router == nullptr || !router->ready()) {
        throw std::runtime_error("the I2P router is still building tunnels");
    }
    const std::string blob = sign(challenge);
    log::info("sending a login signature to {}", log::redact(callback->host));
    return postLoginOverI2p(*router, *callback, challenge, blob, tunnelPrivacy(), owner_);
}

}  // namespace bazarish::client
