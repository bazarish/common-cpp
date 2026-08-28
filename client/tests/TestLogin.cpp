// Bazarish project (c) 2026
#include "Session.hpp"

#include <bazarish/Bytes.hpp>

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
        const std::string challenge = "portal-challenge-" + toHex(randomBytes(16));

        const std::string blob = session.signLogin(challenge);
        CHECK(!blob.empty());

        // Round-trip: the verifier recovers exactly this user's fingerprint.
        CHECK(verifyLoginBlob(blob, now(), challenge) == fingerprint);

        // A signature bound to one challenge does not authenticate another.
        CHECK_THROWS(verifyLoginBlob(blob, now(), "a-different-challenge"));

        // A tampered blob is rejected.
        CHECK_THROWS(verifyLoginBlob(blob + "x", now(), challenge));

        // Stale beyond the auth freshness window is rejected (replay containment).
        CHECK_THROWS(verifyLoginBlob(blob, now() + 100000, challenge));
    }

    fs::remove_all(dir);
    std::printf("TestLogin: all checks passed\n");
    return 0;
}
