// Bazarish project (c) 2026
#include "Authorship.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>

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
    signAuthorship(content, author, /*withKeys=*/true);
    CHECK(content.contains(kAuthorshipField));
    CHECK(authorOf(content) == author.fingerprint());
}

// Changing anything at all invalidates it - the whole envelope is signed, not a
// chosen part of it.
void testTamperedContentIsRefused()
{
    const Identity author = Identity::generate();
    nlohmann::json content = message(author.fingerprint(), "pay me 5");
    signAuthorship(content, author, /*withKeys=*/true);

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
    signAuthorship(mine, author, /*withKeys=*/true);
    nlohmann::json theirs = message(stranger.fingerprint(), "theirs");
    signAuthorship(theirs, stranger, /*withKeys=*/true);

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
    signAuthorship(content, author, /*withKeys=*/true);
    nlohmann::json halved = content;
    halved[kAuthorshipField].erase("p");
    CHECK_THROWS(authorOf(halved));
    // A classical signature alone is not enough - both halves or nothing.
    nlohmann::json classicalOnly = content;
    classicalOnly[kAuthorshipField]["p"] = content.at(kAuthorshipField).at("c");
    CHECK_THROWS(authorOf(classicalOnly));
}

// Keys the reader already has do not travel: a correspondent needs them once,
// and they are a quarter of the block.
void testKeysTravelOnlyWhenAskedFor()
{
    const Identity author = Identity::generate();
    nlohmann::json introduction = message(author.fingerprint(), "hello");
    signAuthorship(introduction, author, /*withKeys=*/true);
    const IdentityKeys carried = keysIn(introduction);
    CHECK(!carried.empty());
    CHECK(authorOf(introduction) == author.fingerprint());

    nlohmann::json later = message(author.fingerprint(), "hello again");
    signAuthorship(later, author, /*withKeys=*/false);
    CHECK(keysIn(later).empty());
    // Nothing to check it against on its own...
    CHECK_THROWS(authorOf(later));
    // ...but the keys the reader kept name the same author.
    CHECK(authorOf(later, carried) == author.fingerprint());
    // Somebody else's keys do not.
    const Identity stranger = Identity::generate();
    nlohmann::json theirs = message(stranger.fingerprint(), "x");
    signAuthorship(theirs, stranger, /*withKeys=*/true);
    CHECK_THROWS(authorOf(later, keysIn(theirs)));
}

// What it costs, said out loud: every message pays the first figure, and every
// size limit has to leave room for the second.
void testWhatTheBlockCosts()
{
    const Identity author = Identity::generate();
    nlohmann::json bareContent = message(author.fingerprint(), "hello");
    const std::size_t bare = nlohmann::json::to_cbor(bareContent).size();

    nlohmann::json signedOnly = bareContent;
    signAuthorship(signedOnly, author, /*withKeys=*/false);
    const std::size_t withoutKeys = nlohmann::json::to_cbor(signedOnly).size() - bare;

    nlohmann::json introduced = bareContent;
    signAuthorship(introduced, author, /*withKeys=*/true);
    const std::size_t withKeys = nlohmann::json::to_cbor(introduced).size() - bare;

    std::printf("TestAuthorship: signatures %zu bytes, with keys %zu bytes\n",
        withoutKeys, withKeys);
    CHECK(withoutKeys < kAuthorshipBytes);
    CHECK(withKeys < kAuthorshipWithKeysBytes);
}

}  // namespace

int main()
{
    testSignedContentNamesItsAuthor();
    testTamperedContentIsRefused();
    testAnotherAuthorsBlockIsRefused();
    testMissingOrBrokenBlockIsRefused();
    testKeysTravelOnlyWhenAskedFor();
    testWhatTheBlockCosts();
    std::printf("TestAuthorship: all checks passed\n");
    return 0;
}
