// Bazarish project (c) 2026
#include "LoginSigner.hpp"

#include <bazarish/Log.hpp>

#include <ctime>
#include <utility>

namespace bazarish::client {

LoginSigner::LoginSigner(Identity identity)
    : identity_(std::move(identity))
{
}

std::string signLoginChallenge(const Identity& identity, const std::string& challenge)
{
    const service::LoginConsumer consumer = service::readLoginConsumer(challenge);
    std::string places;
    for (const std::string& place : consumer.place) {
        places += places.empty() ? place : ", " + place;
    }
    log::info("signing a login for \"{}\" at {} as {}", consumer.name, places,
        consumer.role);
    return service::signLoginBlob(
        identity, static_cast<std::int64_t>(std::time(nullptr)), challenge);
}

std::string LoginSigner::sign(const std::string& challenge) const
{
    return signLoginChallenge(identity_, challenge);
}

}  // namespace bazarish::client
