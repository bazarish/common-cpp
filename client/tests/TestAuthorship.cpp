// Bazarish project (c) 2026
#include "Authorship.hpp"
#include "DeviceTestKit.hpp"

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

constexpr std::size_t kAuthorshipBytes = 5120;
constexpr std::size_t kAuthorshipWithCertBytes = 16384;

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

using devicetest::Account;

void testSignedContentNamesItsAuthor()
{
    const Account author;
    nlohmann::json content = message(author.fingerprint(), "hello");
    signAuthorship(content, author.device, /*withCert=*/false);
    CHECK(content.contains(kAuthorshipField));
    CHECK(authorDevice(content) == author.keys.id());
    const Author signedBy = authorOf(content, author.book());
    CHECK(signedBy.account == author.fingerprint());
    CHECK(signedBy.device == author.keys.id());
}

void testTamperedContentIsRefused()
{
    const Account author;
    nlohmann::json content = message(author.fingerprint(), "pay me 5");
    signAuthorship(content, author.device, /*withCert=*/false);

    nlohmann::json edited = content;
    edited["text"] = "pay me 500";
    CHECK_THROWS(authorOf(edited, author.book()));

    nlohmann::json relabelled = content;
    relabelled["from"] = Identity::generate().fingerprint();
    CHECK_THROWS(authorOf(relabelled, author.book()));

    nlohmann::json extended = content;
    extended["bootstrap"] = {{"dest", "somewhere.b32.i2p"}};
    CHECK_THROWS(authorOf(extended, author.book()));
}

void testAnotherAuthorsBlockIsRefused()
{
    const Account author;
    const Account stranger;
    nlohmann::json mine = message(author.fingerprint(), "mine");
    signAuthorship(mine, author.device, /*withCert=*/true);
    nlohmann::json theirs = message(stranger.fingerprint(), "theirs");
    signAuthorship(theirs, stranger.device, /*withCert=*/true);

    nlohmann::json stolen = mine;
    stolen[kAuthorshipField] = theirs.at(kAuthorshipField);
    CHECK_THROWS(authorOf(stolen, author.book()));

    CHECK(authorOf(theirs, DeviceBook{}).account == stranger.fingerprint());
    CHECK_THROWS(authorOf(theirs, author.book()));

    nlohmann::json unlisted = message(author.fingerprint(), "unlisted");
    signAuthorship(unlisted, stranger.device, /*withCert=*/false);
    CHECK_THROWS(authorOf(unlisted, author.book()));
}

void testMissingOrBrokenBlockIsRefused()
{
    const Account author;
    CHECK_THROWS(authorOf(message(author.fingerprint(), "unsigned"), author.book()));

    nlohmann::json content = message(author.fingerprint(), "signed");
    signAuthorship(content, author.device, /*withCert=*/false);
    nlohmann::json halved = content;
    halved[kAuthorshipField].erase("p");
    CHECK_THROWS(authorOf(halved, author.book()));
    nlohmann::json classicalOnly = content;
    classicalOnly[kAuthorshipField]["p"] = content.at(kAuthorshipField).at("c");
    CHECK_THROWS(authorOf(classicalOnly, author.book()));
    nlohmann::json renamed = content;
    renamed[kAuthorshipField]["d"] = "aaaaaaaaaa";
    CHECK_THROWS(authorOf(renamed, author.book()));
}

void testCertTravelsOnlyWhenAskedFor()
{
    const Account author;
    nlohmann::json introduction = message(author.fingerprint(), "hello");
    signAuthorship(introduction, author.device, /*withCert=*/true);
    CHECK(carriedCert(introduction) == author.certDer);
    CHECK(authorOf(introduction, DeviceBook{}).account == author.fingerprint());

    nlohmann::json later = message(author.fingerprint(), "hello again");
    signAuthorship(later, author.device, /*withCert=*/false);
    CHECK(carriedCert(later).empty());
    CHECK_THROWS(authorOf(later, DeviceBook{}));
    DeviceBook learned;
    learned.take({carriedCert(introduction)}, std::nullopt);
    CHECK(authorOf(later, learned).account == author.fingerprint());
}

void testRevokedDeviceIsRefused()
{
    const Account author;
    DeviceBook book = author.book();
    nlohmann::json content = message(author.fingerprint(), "hello");
    signAuthorship(content, author.device, /*withCert=*/true);
    CHECK(authorOf(content, book).account == author.fingerprint());
    book.take({}, RevocationList::issue(author.root, 1, {author.keys.id()}, devicetest::kIssuedAt));
    CHECK_THROWS(authorOf(content, book));
}

void testWhatTheBlockCosts()
{
    const Account author;
    nlohmann::json bareContent = message(author.fingerprint(), "hello");
    const std::size_t bare = nlohmann::json::to_cbor(bareContent).size();

    nlohmann::json signedOnly = bareContent;
    signAuthorship(signedOnly, author.device, /*withCert=*/false);
    const std::size_t withoutCert = nlohmann::json::to_cbor(signedOnly).size() - bare;

    nlohmann::json introduced = bareContent;
    signAuthorship(introduced, author.device, /*withCert=*/true);
    const std::size_t withCert = nlohmann::json::to_cbor(introduced).size() - bare;

    std::printf("TestAuthorship: signatures %zu bytes, with the certificate %zu bytes\n",
        withoutCert, withCert);
    CHECK(withoutCert < kAuthorshipBytes);
    CHECK(withCert < kAuthorshipWithCertBytes);
}

}  // namespace

int main()
{
    testSignedContentNamesItsAuthor();
    testTamperedContentIsRefused();
    testAnotherAuthorsBlockIsRefused();
    testMissingOrBrokenBlockIsRefused();
    testCertTravelsOnlyWhenAskedFor();
    testRevokedDeviceIsRefused();
    testWhatTheBlockCosts();
    std::printf("TestAuthorship: all checks passed\n");
    return 0;
}
