// Bazarish project (c) 2026
#include "LoginSigner.hpp"

#include "FederationFetch.hpp"
#include "I2pRouter.hpp"

#include <bazarish/Links.hpp>
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
    const service::KeyedLoginLink keyed = service::splitLoginKey(challenge);
    if (!keyed.key.has_value()) {
        throw std::runtime_error("this link names no key to send the signature under");
    }
    bazarish::i2p::Router& router = readySharedI2pRouter();
    const std::string blob = sign(challenge);
    log::info("sending a login signature to {}", log::redact(callback->host));
    return postLoginOverI2p(router, *callback,
        service::sealLoginAnswer(*keyed.key, {canonicalLink(keyed.link), blob}), tunnelPrivacy(),
        owner_);
}

std::optional<std::string> LoginSigner::fetch(
    const std::string& link, const std::atomic<bool>& cancelled) const
{
    const std::optional<service::LoginCallback> address = service::readLoginChallengeLink(link);
    if (!address) {
        throw std::runtime_error("this is not a link to a challenge");
    }
    const std::optional<Bytes> key = service::splitLoginKey(link).key;
    if (!key.has_value()) {
        throw std::runtime_error("this link names no key to fetch the challenge under");
    }
    bazarish::i2p::Router& router = readySharedI2pRouter();
    log::info("fetching a login challenge from {}", log::redact(address->host));
    const std::optional<Bytes> sealed
        = getLoginChallengeOverI2p(router, *address, tunnelPrivacy(), owner_, cancelled);
    if (!sealed) {
        return std::nullopt;
    }
    const std::string challenge = service::openLoginChallenge(*key, *sealed);
    service::requireChallengeReturnsTo(challenge, address->host);
    if (service::splitLoginKey(challenge).key.has_value()) {
        throw std::runtime_error("the fetched challenge carries a key of its own");
    }
    return service::withLoginKey(challenge, *key);
}

}  // namespace bazarish::client
