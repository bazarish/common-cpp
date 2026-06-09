// Bazarish project (c) 2026
#include "bazarish/Address.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include "TestUtil.hpp"

using namespace bazarish;

int main()
{
    const std::string fingerprint = toBase32(Bytes(32, 0x42));
    const std::string serverFingerprint = toBase32(Bytes(32, 0x17));
    CHECK(isFingerprint(fingerprint));
    CHECK(!isFingerprint("alice"));
    CHECK(!isFingerprint(fingerprint + "a"));

    CHECK(isAlias("alice"));
    CHECK(isAlias("a"));
    CHECK(isAlias("alice.bob-42_x"));
    CHECK(!isAlias(""));
    CHECK(!isAlias("Alice"));
    CHECK(!isAlias(".alice"));
    CHECK(!isAlias("alice-"));
    CHECK(!isAlias(std::string(kAliasMaxLength + 1, 'a')));

    // Fully qualified fingerprint address.
    const std::optional<Address> full = parseAddress(fingerprint + "@" + serverFingerprint);
    CHECK(full.has_value());
    CHECK(full->kind == Address::Kind::kFingerprint);
    CHECK(full->local == fingerprint);
    CHECK(full->server == serverFingerprint);
    CHECK(formatAddress(full.value()) == fingerprint + "@" + serverFingerprint);

    // Alias at a specific server.
    const std::optional<Address> aliasAt = parseAddress("alice@" + serverFingerprint);
    CHECK(aliasAt.has_value());
    CHECK(aliasAt->kind == Address::Kind::kAlias);
    CHECK(aliasAt->server == serverFingerprint);

    // Main-server alias: no @server part.
    const std::optional<Address> mainAlias = parseAddress("alice");
    CHECK(mainAlias.has_value());
    CHECK(mainAlias->kind == Address::Kind::kAlias);
    CHECK(mainAlias->server.empty());
    CHECK(formatAddress(mainAlias.value()) == "alice");

    // Rejects: bare fingerprint (nowhere to deliver), bad server part,
    // double @, bad local part.
    CHECK(!parseAddress(fingerprint).has_value());
    CHECK(!parseAddress("alice@notaserver").has_value());
    CHECK(!parseAddress("alice@" + serverFingerprint + "@x").has_value());
    CHECK(!parseAddress("Alice@" + serverFingerprint).has_value());
    CHECK(!parseAddress("").has_value());
    CHECK(!parseAddress("@" + serverFingerprint).has_value());

    return 0;
}
