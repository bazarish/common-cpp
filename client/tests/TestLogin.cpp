// Bazarish project (c) 2026
#include "Session.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/LoginChallenge.hpp>
#include <bazarish/Portal.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

#define CHECK_THROWS(expression)                                                       \
    do {                                                                               \
        bool thrown = false;                                                           \
        try {                                                                          \
            (void)(expression);                                                        \
        } catch (const std::exception&) {                                              \
            thrown = true;                                                             \
        }                                                                              \
        if (!thrown) {                                                                 \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d\n", __FILE__, __LINE__); \
            std::exit(1);                                                              \
        }                                                                              \
    } while (false)

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

// A challenge shaped like a real one but for the field under test.
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

    // The account is removed once the session holding it is gone: an open
    // database file is not one every platform lets go of.
    {
        const Session session = Session::create(dir, "pw", "alice");
        const std::string fingerprint = session.fingerprint();
        service::LoginChallenge portal("portal-secret", portalConsumer());
        const std::string challenge = portal.issue(now());

        const std::string blob = session.signLogin(challenge);
        CHECK(!blob.empty());

        // Round-trip: the verifier recovers exactly this user's fingerprint.
        CHECK(service::verifyLoginBlob(blob, now(), challenge) == fingerprint);

        // A signature bound to one challenge does not authenticate another.
        CHECK_THROWS(service::verifyLoginBlob(blob, now(), portal.issue(now())));

        // A tampered blob is rejected.
        CHECK_THROWS(service::verifyLoginBlob(blob + "x", now(), challenge));

        // Stale beyond the auth freshness window is rejected (replay containment).
        CHECK_THROWS(service::verifyLoginBlob(blob, now() + 100000, challenge));

        // Fail closed. A challenge that does not name who consumes the signature
        // is not signed at all: the user would have nothing to compare with the
        // site in front of them.
        CHECK_THROWS(session.signLogin("portal-challenge-" + toHex(randomBytes(16))));
        CHECK_THROWS(session.signLogin(encodedChallenge(
            {{"v", service::kLoginChallengeVersion}, {"nonce", "abc"}, {"ts", now()}})));

        // Nor is one that names a consumer only in part.
        service::LoginConsumer partial = portalConsumer();
        partial.role.clear();
        CHECK_THROWS(session.signLogin(encodedChallenge(envelopeWith(partial))));

        // A field long enough to push the rest out of the window, or one that
        // could paint a line of its own, is refused rather than shown.
        service::LoginConsumer overlong = portalConsumer();
        overlong.name = std::string(service::kConsumerNameMax + 1, 'a');
        CHECK_THROWS(session.signLogin(encodedChallenge(envelopeWith(overlong))));
        service::LoginConsumer painted = portalConsumer();
        painted.name = "Your server\nplace: somewhere-else.i2p";
        CHECK_THROWS(session.signLogin(encodedChallenge(envelopeWith(painted))));

        // A challenge of another version is not read by guesswork.
        nlohmann::json future = envelopeWith(portalConsumer());
        future["v"] = service::kLoginChallengeVersion + 1;
        CHECK_THROWS(session.signLogin(encodedChallenge(future)));
    }

    fs::remove_all(dir);
    std::printf("TestLogin: all checks passed\n");
    return 0;
}
