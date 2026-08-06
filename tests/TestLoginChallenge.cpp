// Bazarish project (c) 2026
#include <bazarish/LoginChallenge.hpp>
#include <bazarish/Portal.hpp>

#include <bazarish/Crypto.hpp>

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

// A challenge issued here, signed by the user, verifies once and recovers the
// fingerprint; replaying the same challenge is rejected (single use).
void testHappyPathAndReplay()
{
    const Identity identity = Identity::generate();
    LoginChallenge portal("portal-secret", "server-fp");
    const std::int64_t t = 5000;

    const std::string challenge = portal.issue(t);
    const std::string blob = signLoginBlob(identity, t, challenge);

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
        LoginChallenge portal("portal-secret", "server-fp");
        const std::string challenge = portal.issue(t);
        const std::string blob = signLoginBlob(identity, t, challenge);
        CHECK_THROWS(portal.verify(challenge, "not-a-valid-blob", t));  // bad signature
        CHECK(portal.verify(challenge, blob, t) == identity.fingerprint());  // nonce not burned
    }
    {
        LoginChallenge issuer("portal-secret", "server-fp");
        const std::string challenge = issuer.issue(t);
        const std::string blob = signLoginBlob(identity, t, challenge);

        // A challenge for one server does not authenticate against another.
        LoginChallenge otherServer("portal-secret", "other-server");
        CHECK_THROWS(otherServer.verify(challenge, blob, t));

        // A forged challenge (not HMAC'd by this portal's secret) is rejected.
        LoginChallenge otherSecret("different-secret", "server-fp");
        CHECK_THROWS(otherSecret.verify(challenge, blob, t));

        // Outside the freshness window.
        CHECK_THROWS(issuer.verify(challenge, blob, t + 100000));
    }
}

}  // namespace

int main()
{
    testHappyPathAndReplay();
    testRejections();
    std::printf("TestLoginChallenge: all checks passed\n");
    return 0;
}
