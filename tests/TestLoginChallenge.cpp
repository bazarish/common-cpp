// Bazarish project (c) 2026
#include <bazarish/LoginChallenge.hpp>
#include <bazarish/Portal.hpp>

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>

using namespace bazarish;
using namespace bazarish::service;

namespace {

LoginConsumer panel()
{
    return LoginConsumer{"Bazarish admin panel", {"http://127.0.0.1:8460"}, "Administrator"};
}

void testHappyPathAndReplay()
{
    const Identity identity = Identity::generate();
    LoginChallenge portal("portal-secret", panel());
    const std::int64_t t = 5000;

    const std::string challenge = portal.issue(t);
    const std::string blob = signLoginBlob(identity, t, challenge);

    const LoginConsumer named = readLoginConsumer(challenge);
    CHECK(named.name == panel().name);
    CHECK(named.place == panel().place);
    CHECK(named.role == panel().role);

    CHECK(portal.verify(challenge, blob, t) == identity.fingerprint());
    CHECK_THROWS(portal.verify(challenge, blob, t));
}

void testRejections()
{
    const Identity identity = Identity::generate();
    const std::int64_t t = 5000;

    {
        LoginChallenge portal("portal-secret", panel());
        const std::string challenge = portal.issue(t);
        const std::string blob = signLoginBlob(identity, t, challenge);
        CHECK_THROWS(portal.verify(challenge, "not-a-valid-blob", t));
        CHECK(portal.verify(challenge, blob, t) == identity.fingerprint());
    }
    {
        LoginChallenge issuer("portal-secret", panel());
        const std::string challenge = issuer.issue(t);
        const std::string blob = signLoginBlob(identity, t, challenge);

        LoginConsumer other = panel();
        other.name = "Bazarish admin panel - south fleet";
        CHECK_THROWS(LoginChallenge("portal-secret", other).verify(challenge, blob, t));
        other = panel();
        other.place = {"http://127.0.0.1:9460"};
        CHECK_THROWS(LoginChallenge("portal-secret", other).verify(challenge, blob, t));
        other = panel();
        other.role = "Account owner";
        CHECK_THROWS(LoginChallenge("portal-secret", other).verify(challenge, blob, t));

        LoginChallenge otherSecret("different-secret", panel());
        CHECK_THROWS(otherSecret.verify(challenge, blob, t));

        CHECK_THROWS(issuer.verify(challenge, blob, t + 100000));
    }
}

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

    CHECK_THROWS(issuer.verify(relabelled, blob, t));
    CHECK_THROWS(LoginChallenge("portal-secret", forged).verify(relabelled, blob, t));
}

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

    LoginConsumer blankPlace = panel();
    blankPlace.place = {"https://panel.example", ""};
    CHECK_THROWS(LoginChallenge("portal-secret", blankPlace));

    LoginConsumer crowded = panel();
    crowded.place.clear();
    for (std::size_t i = 0; i <= kConsumerPlacesMax; ++i) {
        crowded.place.push_back("https://panel" + std::to_string(i) + ".example");
    }
    CHECK_THROWS(LoginChallenge("portal-secret", crowded));
    crowded.place.pop_back();
    CHECK(crowded.place.size() == kConsumerPlacesMax);
    LoginChallenge atTheCap("portal-secret", crowded);
    CHECK(readLoginConsumer(atTheCap.issue(5000)).place == crowded.place);
}

void testEveryPlaceIsSigned()
{
    const Identity identity = Identity::generate();
    const LoginConsumer both{
        "Bazarish alias registry", {"https://alias.example", "http://alias.b32.i2p"}, "Alias owner"};
    LoginChallenge portal("portal-secret", both);
    const std::int64_t t = 5000;

    const std::string challenge = portal.issue(t);
    CHECK(readLoginConsumer(challenge).place == both.place);
    const std::string blob = signLoginBlob(identity, t, challenge);
    CHECK(portal.verify(challenge, blob, t) == identity.fingerprint());

    // The list is what the tag covers, so dropping or reordering it is a
    // different consumer and the signature stops verifying.
    LoginConsumer fewer = both;
    fewer.place = {"https://alias.example"};
    CHECK_THROWS(LoginChallenge("portal-secret", fewer).verify(challenge, blob, t));
    LoginConsumer swapped = both;
    std::swap(swapped.place.front(), swapped.place.back());
    CHECK_THROWS(LoginChallenge("portal-secret", swapped).verify(challenge, blob, t));
}

void testConsumerChangedWhileRunning()
{
    const Identity identity = Identity::generate();
    LoginChallenge portal("portal-secret", panel());
    const std::int64_t t = 5000;

    const std::string before = portal.issue(t);
    const std::string blobBefore = signLoginBlob(identity, t, before);

    const LoginConsumer renamed{"Bazarish alpha", {"https://alpha.example"}, "Administrator"};
    portal.setConsumer(renamed);
    CHECK(portal.consumer() == renamed);

    const std::string after = portal.issue(t);
    CHECK(readLoginConsumer(after).name == renamed.name);
    CHECK(readLoginConsumer(after).place == renamed.place);
    CHECK(portal.verify(after, signLoginBlob(identity, t, after), t) == identity.fingerprint());

    CHECK_THROWS(portal.verify(before, blobBefore, t));

    LoginConsumer roleless = renamed;
    roleless.role.clear();
    CHECK_THROWS(portal.setConsumer(roleless));
    CHECK(portal.consumer() == renamed);
}

void testChallengePastedAsBlob()
{
    LoginChallenge portal("portal-secret", panel());
    const std::int64_t t = 5000;
    const std::string challenge = portal.issue(t);

    std::string complaint;
    try {
        (void)portal.verify(challenge, challenge, t);
    } catch (const std::exception& error) {
        complaint = error.what();
    }
    CHECK(complaint.find("this is the challenge, not the signature") != std::string::npos);

    // And something that is not base64 of JSON at all says so in words too.
    std::string other;
    try {
        (void)portal.verify(challenge, "paste-went-wrong", t);
    } catch (const std::exception& error) {
        other = error.what();
    }
    CHECK(other.find("not a signature") != std::string::npos);
}

}  // namespace

int main()
{
    testHappyPathAndReplay();
    testRejections();
    testRelabelling();
    testIncompleteConsumerRefused();
    testEveryPlaceIsSigned();
    testConsumerChangedWhileRunning();
    testChallengePastedAsBlob();
    std::printf("TestLoginChallenge: all checks passed\n");
    return 0;
}
