// Bazarish project (c) 2026
#include "Session.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/LoginChallenge.hpp>
#include <bazarish/Portal.hpp>

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

namespace {

std::int64_t now()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

service::LoginConsumer portalConsumer()
{
    return service::LoginConsumer{"Bazarish service node", "http://node.example", "Account owner"};
}

std::string encodedChallenge(const nlohmann::json& envelope)
{
    const std::string text = envelope.dump();
    return toBase64(Bytes(text.begin(), text.end()));
}

nlohmann::json envelopeWith(const service::LoginConsumer& consumer)
{
    return nlohmann::json{
        {"v", service::kLoginChallengeVersion},
        {"nonce", toHex(randomBytes(16))},
        {"ts", now()},
        {"consumer",
            {{"name", consumer.name}, {"place", consumer.place}, {"role", consumer.role}}},
        {"tag", "irrelevant-to-the-client"},
    };
}

}  // namespace

int main()
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("bazarish-login-" + toHex(randomBytes(8)));

    {
        const Session session = Session::create(dir, "pw", "alice");
        const std::string fingerprint = session.fingerprint();
        service::LoginChallenge portal("portal-secret", portalConsumer());
        const std::string challenge = portal.issue(now());

        const std::string blob = session.signLogin(challenge);
        CHECK(!blob.empty());

        CHECK(service::verifyLoginBlob(blob, now(), challenge) == fingerprint);

        CHECK_THROWS(service::verifyLoginBlob(blob, now(), portal.issue(now())));

        CHECK_THROWS(service::verifyLoginBlob(blob + "x", now(), challenge));

        CHECK_THROWS(service::verifyLoginBlob(blob, now() + 100000, challenge));

        CHECK_THROWS(session.signLogin("portal-challenge-" + toHex(randomBytes(16))));
        CHECK_THROWS(session.signLogin(encodedChallenge(
            {{"v", service::kLoginChallengeVersion}, {"nonce", "abc"}, {"ts", now()}})));

        service::LoginConsumer partial = portalConsumer();
        partial.role.clear();
        CHECK_THROWS(session.signLogin(encodedChallenge(envelopeWith(partial))));

        service::LoginConsumer overlong = portalConsumer();
        overlong.name = std::string(service::kConsumerNameMax + 1, 'a');
        CHECK_THROWS(session.signLogin(encodedChallenge(envelopeWith(overlong))));
        service::LoginConsumer painted = portalConsumer();
        painted.name = "Your server\nplace: somewhere-else.i2p";
        CHECK_THROWS(session.signLogin(encodedChallenge(envelopeWith(painted))));

        nlohmann::json future = envelopeWith(portalConsumer());
        future["v"] = service::kLoginChallengeVersion + 1;
        CHECK_THROWS(session.signLogin(encodedChallenge(future)));
    }

    fs::remove_all(dir);
    std::printf("TestLogin: all checks passed\n");
    return 0;
}
