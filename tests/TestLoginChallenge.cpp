// Bazarish project (c) 2026
#include <bazarish/LoginChallenge.hpp>
#include <bazarish/Portal.hpp>

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
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
using namespace bazarish::service;

namespace {

LoginConsumer panel()
{
    return LoginConsumer{"Bazarish admin panel", "http://127.0.0.1:8460", "Administrator"};
}

// A challenge issued here, signed by the user, verifies once and recovers the
// fingerprint; replaying the same challenge is rejected (single use).
void testHappyPathAndReplay()
{
    const Identity identity = Identity::generate();
    LoginChallenge portal("portal-secret", panel());
    const std::int64_t t = 5000;

    const std::string challenge = portal.issue(t);
    const std::string blob = signLoginBlob(identity, t, challenge);

    // What the portal checks is what the client would have shown the user.
    const LoginConsumer named = readLoginConsumer(challenge);
    CHECK(named.name == panel().name);
    CHECK(named.place == panel().place);
    CHECK(named.role == panel().role);

    CHECK(portal.verify(challenge, blob, t) == identity.fingerprint());
    CHECK_THROWS(portal.verify(challenge, blob, t));  // replay
}

// Forged / mis-targeted / stale challenges and bad signatures are rejected; a
// failed signature attempt does not burn an otherwise-valid challenge.
void testRejections()
{
    const Identity identity = Identity::generate();
    const std::int64_t t = 5000;

    {
        LoginChallenge portal("portal-secret", panel());
        const std::string challenge = portal.issue(t);
        const std::string blob = signLoginBlob(identity, t, challenge);
        CHECK_THROWS(portal.verify(challenge, "not-a-valid-blob", t));  // bad signature
        CHECK(portal.verify(challenge, blob, t) == identity.fingerprint());  // nonce not burned
    }
    {
        LoginChallenge issuer("portal-secret", panel());
        const std::string challenge = issuer.issue(t);
        const std::string blob = signLoginBlob(identity, t, challenge);

        // A challenge for one consumer does not authenticate against another,
        // and it is enough for any one of the three fields to differ.
        LoginConsumer other = panel();
        other.name = "Bazarish admin panel - south fleet";
        CHECK_THROWS(LoginChallenge("portal-secret", other).verify(challenge, blob, t));
        other = panel();
        other.place = "http://127.0.0.1:9460";
        CHECK_THROWS(LoginChallenge("portal-secret", other).verify(challenge, blob, t));
        other = panel();
        other.role = "Account owner";
        CHECK_THROWS(LoginChallenge("portal-secret", other).verify(challenge, blob, t));

        // A forged challenge (not HMAC'd by this portal's secret) is rejected.
        LoginChallenge otherSecret("different-secret", panel());
        CHECK_THROWS(otherSecret.verify(challenge, blob, t));

        // Outside the freshness window.
        CHECK_THROWS(issuer.verify(challenge, blob, t + 100000));
    }
}

// Re-labelling a captured challenge is what the tag is for: whoever shows a user
// one place cannot hand the signature to another.
void testRelabelling()
{
    const Identity identity = Identity::generate();
    const std::int64_t t = 5000;
    LoginChallenge issuer("portal-secret", panel());
    const std::string challenge = issuer.issue(t);

    const Bytes raw = fromBase64(challenge);
    nlohmann::json envelope = nlohmann::json::parse(raw.begin(), raw.end());
    LoginConsumer forged = panel();
    forged.name = "Somewhere else entirely";
    envelope["consumer"]["name"] = forged.name;
    const std::string text = envelope.dump();
    const std::string relabelled = toBase64(Bytes(text.begin(), text.end()));
    const std::string blob = signLoginBlob(identity, t, relabelled);

    // The issuer sees a label that is not its own...
    CHECK_THROWS(issuer.verify(relabelled, blob, t));
    // ...and a portal wearing the forged label cannot check the tag.
    CHECK_THROWS(LoginChallenge("portal-secret", forged).verify(relabelled, blob, t));
}

// A portal that will not say who it is has no business asking for a signature,
// so an incomplete consumer stops it at construction rather than at login.
void testIncompleteConsumerRefused()
{
    LoginConsumer nameless = panel();
    nameless.name.clear();
    CHECK_THROWS(LoginChallenge("portal-secret", nameless));
    LoginConsumer placeless = panel();
    placeless.place.clear();
    CHECK_THROWS(LoginChallenge("portal-secret", placeless));
    LoginConsumer roleless = panel();
    roleless.role.clear();
    CHECK_THROWS(LoginChallenge("portal-secret", roleless));
}

// An operator renames the deployment while it runs: new challenges carry the new
// words, and one issued under the old ones stops verifying rather than buying a
// session under a name nobody agreed to.
void testConsumerChangedWhileRunning()
{
    const Identity identity = Identity::generate();
    LoginChallenge portal("portal-secret", panel());
    const std::int64_t t = 5000;

    const std::string before = portal.issue(t);
    const std::string blobBefore = signLoginBlob(identity, t, before);

    const LoginConsumer renamed{"Bazarish alpha", "https://alpha.example", "Administrator"};
    portal.setConsumer(renamed);
    CHECK(portal.consumer() == renamed);

    const std::string after = portal.issue(t);
    CHECK(readLoginConsumer(after).name == renamed.name);
    CHECK(readLoginConsumer(after).place == renamed.place);
    CHECK(portal.verify(after, signLoginBlob(identity, t, after), t) == identity.fingerprint());

    CHECK_THROWS(portal.verify(before, blobBefore, t));

    // A consumer the portal could not stand behind never replaces the one it has.
    LoginConsumer roleless = renamed;
    roleless.role.clear();
    CHECK_THROWS(portal.setConsumer(roleless));
    CHECK(portal.consumer() == renamed);
}

}  // namespace

int main()
{
    testHappyPathAndReplay();
    testRejections();
    testRelabelling();
    testIncompleteConsumerRefused();
    testConsumerChangedWhileRunning();
    std::printf("TestLoginChallenge: all checks passed\n");
    return 0;
}
