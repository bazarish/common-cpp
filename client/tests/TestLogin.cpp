// Bazarish project (c) 2026
#include "Session.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Links.hpp>
#include <bazarish/LoginChallenge.hpp>
#include <bazarish/Portal.hpp>

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <optional>
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
    return service::LoginConsumer{
        "Bazarish service node", {"http://node.example"}, "Account owner"};
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

std::string encodedChallenge(const nlohmann::json& envelope)
{
    return service::encodeLoginChallenge(envelope.dump());
}

const std::string kSiteHost = std::string(52, 'a') + ".b32.i2p";
const std::string kBlindedHost = std::string(56, 'b') + ".b32.i2p";

service::LoginConsumer siteConsumer()
{
    return service::LoginConsumer{
        "An I2P site", {"https://site.example", "http://" + kSiteHost, kBlindedHost}, "Member"};
}

std::string withCallback(const nlohmann::json& callback)
{
    nlohmann::json envelope = envelopeWith(siteConsumer());
    envelope["callback"] = callback;
    return encodedChallenge(envelope);
}

void testCallbacks(const Session& session)
{
    const std::optional<service::LoginCallback> none
        = service::readLoginCallback(encodedChallenge(envelopeWith(siteConsumer())));
    CHECK(!none.has_value());

    const std::optional<service::LoginCallback> plain
        = service::readLoginCallback(withCallback("http://" + kSiteHost + "/login?step=2&x=%20"));
    CHECK(plain.has_value() && plain->host == kSiteHost && plain->path == "/login?step=2&x=%20");
    const std::optional<service::LoginCallback> blinded
        = service::readLoginCallback(withCallback("http://" + kBlindedHost + "/in"));
    CHECK(blinded.has_value() && blinded->host == kBlindedHost);

    const std::string elsewhere = std::string(52, 'c') + ".b32.i2p";
    for (const std::string& refused : {
             "http://" + elsewhere + "/login",
             "https://" + kSiteHost + "/login",
             "http://" + kSiteHost + ":8080/login",
             "http://" + kSiteHost,
             "http://" + kSiteHost + "/a b",
             "http://" + kSiteHost + "/login#here",
             "http://" + kSiteHost + "/say\"hi\"",
             "http://" + kSiteHost + "/back\\slash",
             "http://" + kSiteHost + "/<b>",
             std::string("http://site.example/login"),
             "http://user@" + kSiteHost + "/login",
         }) {
        CHECK_THROWS(service::readLoginCallback(withCallback(refused)));
        CHECK_THROWS(session.signLogin(withCallback(refused)));
    }
    CHECK_THROWS(service::readLoginCallback(withCallback(42)));

    service::LoginChallenge site("site-secret", siteConsumer());
    const std::string issued = site.issue(now(), "http://" + kSiteHost + "/login");
    CHECK(service::readLoginCallback(issued)->path == "/login");
    CHECK(service::verifyLoginBlob(session.signLogin(issued), now(), issued)
        == session.fingerprint());
    CHECK(site.verify(issued, session.signLogin(issued), now()) == session.fingerprint());
    CHECK_THROWS(site.issue(now(), "http://" + elsewhere + "/login"));
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
        const std::string text = envelopeWith(portalConsumer()).dump();
        CHECK_THROWS(session.signLogin(toBase64(Bytes(text.begin(), text.end()))));
        CHECK_THROWS(session.signLogin(challenge + "&c=x"));
        CHECK_THROWS(session.signLogin(std::string(kInviteUri) + challenge.substr(16)));
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
        service::LoginConsumer separated = portalConsumer();
        separated.name = "Your server\u2028place: somewhere-else.i2p";
        CHECK_THROWS(session.signLogin(encodedChallenge(envelopeWith(separated))));
        service::LoginConsumer paintedPlace = portalConsumer();
        paintedPlace.place = {"http://node.example\nsomewhere-else.i2p"};
        CHECK_THROWS(session.signLogin(encodedChallenge(envelopeWith(paintedPlace))));
        service::LoginConsumer crowded = portalConsumer();
        crowded.place.clear();
        for (std::size_t i = 0; i <= service::kConsumerPlacesMax; ++i) {
            crowded.place.push_back("http://node" + std::to_string(i) + ".example");
        }
        CHECK_THROWS(session.signLogin(encodedChallenge(envelopeWith(crowded))));

        service::LoginConsumer both = portalConsumer();
        both.place = {"https://node.example", "http://node.b32.i2p"};
        CHECK(!session.signLogin(encodedChallenge(envelopeWith(both))).empty());

        nlohmann::json future = envelopeWith(portalConsumer());
        future["v"] = service::kLoginChallengeVersion + 1;
        CHECK_THROWS(session.signLogin(encodedChallenge(future)));

        testCallbacks(session);
    }

    fs::remove_all(dir);
    std::printf("TestLogin: all checks passed\n");
    return 0;
}
