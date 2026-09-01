// Bazarish project (c) 2026
#include "Authorship.hpp"

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

#define CHECK_THROWS(expression)                                                        \
    do {                                                                                \
        bool thrown = false;                                                            \
        try {                                                                           \
            (void)(expression);                                                          \
        } catch (const std::exception&) {                                               \
            thrown = true;                                                              \
        }                                                                               \
        if (!thrown) {                                                                  \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d\n", __FILE__, __LINE__); \
            std::exit(1);                                                               \
        }                                                                               \
    } while (false)

using namespace bazarish;
using namespace bazarish::client;

namespace {

nlohmann::json message(const std::string& from, const std::string& text)
{
    return nlohmann::json{
        {"v", 1},
        {"type", "text"},
        {"id", "abc123"},
        {"from", from},
        {"sentAt", 1788000000},
        {"text", text},
    };
}

// What the block is for: the content answers for its own author.
void testSignedContentNamesItsAuthor()
{
    const Identity author = Identity::generate();
    nlohmann::json content = message(author.fingerprint(), "hello");
    signAuthorship(content, author);
    CHECK(content.contains(kAuthorshipField));
    CHECK(authorOf(content) == author.fingerprint());
}

// Changing anything at all invalidates it - the whole envelope is signed, not a
// chosen part of it.
void testTamperedContentIsRefused()
{
    const Identity author = Identity::generate();
    nlohmann::json content = message(author.fingerprint(), "pay me 5");
    signAuthorship(content, author);

    nlohmann::json edited = content;
    edited["text"] = "pay me 500";
    CHECK_THROWS(authorOf(edited));

    // The name on it is part of what is signed, so a message cannot be re-labelled
    // as somebody else's - which is the forgery this exists to stop.
    nlohmann::json relabelled = content;
    relabelled["from"] = Identity::generate().fingerprint();
    CHECK_THROWS(authorOf(relabelled));

    // Fields added after signing are not signed, and so are not accepted either.
    nlohmann::json extended = content;
    extended["bootstrap"] = {{"dest", "somewhere.b32.i2p"}};
    CHECK_THROWS(authorOf(extended));
}

// Somebody else's block does not travel: the signature is over these bytes.
void testAnotherAuthorsBlockIsRefused()
{
    const Identity author = Identity::generate();
    const Identity stranger = Identity::generate();
    nlohmann::json mine = message(author.fingerprint(), "mine");
    signAuthorship(mine, author);
    nlohmann::json theirs = message(stranger.fingerprint(), "theirs");
    signAuthorship(theirs, stranger);

    nlohmann::json stolen = mine;
    stolen[kAuthorshipField] = theirs.at(kAuthorshipField);
    CHECK_THROWS(authorOf(stolen));

    // A signature from one identity never names another: the fingerprint comes
    // out of the keys that signed, not out of the message.
    CHECK(authorOf(theirs) == stranger.fingerprint());
    CHECK(authorOf(theirs) != author.fingerprint());
}

// No block at all, or a broken one: there is no author to name.
void testMissingOrBrokenBlockIsRefused()
{
    const Identity author = Identity::generate();
    CHECK_THROWS(authorOf(message(author.fingerprint(), "unsigned")));

    nlohmann::json content = message(author.fingerprint(), "signed");
    signAuthorship(content, author);
    nlohmann::json halved = content;
    halved[kAuthorshipField].erase("p");
    CHECK_THROWS(authorOf(halved));
    // A classical signature alone is not enough - both halves or nothing.
    nlohmann::json classicalOnly = content;
    classicalOnly[kAuthorshipField]["p"] = content.at(kAuthorshipField).at("c");
    CHECK_THROWS(authorOf(classicalOnly));
}

// What it costs, said out loud: every message pays this, and the limits around
// it are set with the figure in hand.
void testWhatTheBlockCosts()
{
    const Identity author = Identity::generate();
    nlohmann::json content = message(author.fingerprint(), "hello");
    const std::size_t bare = nlohmann::json::to_cbor(content).size();
    signAuthorship(content, author);
    const std::size_t signedSize = nlohmann::json::to_cbor(content).size();
    std::printf("TestAuthorship: the block adds %zu bytes to a %zu byte message\n",
        signedSize - bare, bare);
    CHECK(signedSize - bare < kAuthorshipBytes);
}

}  // namespace

int main()
{
    testSignedContentNamesItsAuthor();
    testTamperedContentIsRefused();
    testAnotherAuthorsBlockIsRefused();
    testMissingOrBrokenBlockIsRefused();
    testWhatTheBlockCosts();
    std::printf("TestAuthorship: all checks passed\n");
    return 0;
}
