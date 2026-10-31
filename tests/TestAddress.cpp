// Bazarish project (c) 2026
#include "bazarish/Address.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include "TestUtil.hpp"

using namespace bazarish;

int main()
{
    const std::string fingerprint = toBase32(Bytes(32, 0x42));
    CHECK(isFingerprint(fingerprint));
    CHECK(!isFingerprint("alice"));
    CHECK(!isFingerprint(fingerprint + "a"));

    CHECK(isAlias("alice"));
    CHECK(isAlias("a"));
    CHECK(isAlias("alice42"));
    CHECK(!isAlias("alice.bob"));
    CHECK(!isAlias("alice_bob"));
    CHECK(!isAlias("alice-bob"));
    CHECK(!isAlias(""));
    CHECK(!isAlias("Alice"));
    CHECK(!isAlias(".alice"));
    CHECK(!isAlias("alice-"));
    CHECK(!isAlias(std::string(kAliasMaxLength + 1, 'a')));

    CHECK(normalizeAlias("alice") == "alice");
    CHECK(normalizeAlias("!Alice") == "alice");
    CHECK(normalizeAlias(std::string(kAliasMaxLength, 'A')) == std::string(kAliasMaxLength, 'a'));
    CHECK_THROWS(normalizeAlias(""));
    CHECK_THROWS(normalizeAlias("!"));
    CHECK_THROWS(normalizeAlias(std::string(kAliasMaxLength + 1, 'a')));
    CHECK_THROWS(normalizeAlias("alice.bob"));
    CHECK_THROWS(normalizeAlias("ali!ce"));

    CHECK((parseAliasQuery("!Alice") == AliasQuery{"alice", ""}));
    CHECK((parseAliasQuery("alice-Secret42") == AliasQuery{"alice", "secret42"}));
    CHECK((parseAliasQuery("!a-b") == AliasQuery{"a", "b"}));
    CHECK(aliasQueryText({"alice", "secret42"}) == "alice-secret42");
    CHECK(aliasQueryText({"alice", ""}) == "alice");
    CHECK_THROWS(parseAliasQuery("alice-"));
    CHECK_THROWS(parseAliasQuery("-secret"));
    CHECK_THROWS(parseAliasQuery("alice-se-cret"));
    CHECK_THROWS(parseAliasQuery("alice-sec.ret"));
    CHECK_THROWS(parseAliasQuery("alice-" + std::string(kAliasWordMaxLength + 1, 'w')));
    CHECK(normalizeAliasWord("").empty());
    CHECK(normalizeAliasWord("WoRd") == "word");

    return 0;
}
