// Bazarish project (c) 2026
#include "bazarish/Certificates.hpp"

#include "bazarish/Cms.hpp"

#include "TestUtil.hpp"

#include <stdexcept>

using namespace bazarish;

namespace {

constexpr std::int64_t kNow = 1780000000;
constexpr std::int64_t kThreeDays = 3 * 24 * 3600;

}  // namespace

int main()
{
    const Identity user = Identity::generate();
    const Identity serverRoot = Identity::generate();
    const Key sealing = Key::generateSealing();

    // Contact card round trip: a card with nothing published yet is still a
    // signed statement of who it belongs to.
    const Bytes bareDer = ContactCard::issue(user, kNow);
    const ContactCard bare = ContactCard::verify(bareDer);
    // Whose card it is comes from the signature, not from a claim standing
    // beside it: there is nothing in the body left to disagree with the signer.
    CHECK(bare.fingerprint() == user.fingerprint());
    CHECK(bare.dest.empty());
    CHECK(bare.sealingPublicKeyDer.empty());
    CHECK(bare.servingSealingKeyDer.empty());
    CHECK_THROWS(bare.sealingKey());
    CHECK_THROWS(bare.servingSealingKey());

    // A published card: routing and both keys ride under the one signature, and
    // nothing in it names the server that operates the destination.
    const Key servingSealing = Key::generateSealing();
    const std::string dest = "exampledestination.b32.i2p";
    const Bytes contactDer = ContactCard::issue(
        user, kNow, dest, sealing.publicDer(), servingSealing.publicDer());
    const ContactCard contact = ContactCard::verify(contactDer);
    CHECK(contact.fingerprint() == user.fingerprint());
    CHECK(contact.issuedAt == kNow);
    CHECK(contact.dest == dest);
    CHECK(contact.sealingPublicKeyDer == sealing.publicDer());
    CHECK(contact.sealingKey().publicDer() == sealing.publicDer());
    CHECK(contact.servingSealingKeyDer == servingSealing.publicDer());
    CHECK(contact.servingSealingKey().publicDer() == servingSealing.publicDer());

    // A card is its signer's, and a name written into the body is not consulted:
    // there is nothing there to disagree with the signature. A card somebody else
    // signed is simply theirs, and it is the reader who says whether that is the
    // one they asked for - which is where the check belongs, because only the
    // reader knows whose card they wanted.
    {
        const Identity impostor = Identity::generate();
        const nlohmann::json body = {{"v", kCertificateFormatVersion}, {"t", "contact-card"},
            {"issuedAt", kNow}, {"user", user.fingerprint()}};
        const ContactCard theirs = ContactCard::verify(cms::signJsonHybrid(body, impostor));
        CHECK(theirs.fingerprint() == impostor.fingerprint());
        CHECK(theirs.fingerprint() != user.fingerprint());
    }

    // A signed document that is not a contact card is not read as one, however
    // well its fields happen to line up.
    {
        const nlohmann::json notACard = {{"v", kCertificateFormatVersion}, {"t", "alias"},
            {"issuedAt", kNow}, {"alias", "someone"}};
        CHECK_THROWS(ContactCard::verify(cms::signJsonHybrid(notACard, user)));
        const nlohmann::json untagged = {{"v", kCertificateFormatVersion}};
        CHECK_THROWS(ContactCard::verify(cms::signJsonHybrid(untagged, user)));
    }

    // A card that cannot be placed in time is refused: it could not be compared
    // with the one already held, which is the only reason the stamp is there.
    {
        const nlohmann::json undated
            = {{"v", kCertificateFormatVersion}, {"t", "contact-card"}};
        CHECK_THROWS(ContactCard::verify(cms::signJsonHybrid(undated, user)));
    }

    // Two cards of one person are ordered by the stamp and by nothing else.
    {
        const Bytes olderDer = ContactCard::issue(user, kNow, "old.b32.i2p",
            sealing.publicDer(), servingSealing.publicDer());
        const Bytes newerDer = ContactCard::issue(user, kNow + 1, "new.b32.i2p",
            sealing.publicDer(), servingSealing.publicDer());
        CHECK(ContactCard::verify(olderDer).issuedAt
            < ContactCard::verify(newerDer).issuedAt);
    }

    // Alias certificate round trip, with and without expiry.
    const Bytes aliasDer = AliasCertificate::issue(user, "alice", kNow, std::nullopt);
    const AliasCertificate alias = AliasCertificate::verify(aliasDer);
    CHECK(alias.alias == "alice");
    CHECK(alias.user == user.fingerprint());
    CHECK(!alias.notAfter.has_value());

    const Bytes boundedAliasDer = AliasCertificate::issue(user, "bob", kNow, kNow + kThreeDays);
    const AliasCertificate boundedAlias = AliasCertificate::verify(boundedAliasDer);
    CHECK(boundedAlias.notAfter.has_value());
    CHECK(boundedAlias.notAfter.value() == kNow + kThreeDays);

    // Server card round trip. It names the server and its sealing key and
    // nothing else: the server has no address of its own to advertise, users
    // being reached at their own destinations.
    const Bytes cardDer = ServerCard::issue(serverRoot, sealing, kNow);
    const ServerCard card = ServerCard::verify(cardDer);
    CHECK(card.server == serverRoot.fingerprint());
    CHECK(card.issuedAt == kNow);
    CHECK(card.sealingKey().fingerprint() == sealing.fingerprint());

    // A certificate naming someone else's identity must fail verification:
    // Mallory signs a subscription certificate claiming the victim's UID.
    const Identity mallory = Identity::generate();
    const nlohmann::json forgedBody = {
        {"v", kCertificateFormatVersion},
        {"user", user.fingerprint()},
        {"server", serverRoot.fingerprint()},
        {"issuedAt", kNow},
        {"notAfter", kNow + kThreeDays},
    };
    const Bytes forgedDer = cms::signJsonHybrid(forgedBody, mallory);
    CHECK_THROWS(ContactCard::verify(forgedDer));

    // An unsupported format version must be rejected.
    const nlohmann::json futureBody = {
        {"v", kCertificateFormatVersion + 1},
        {"user", user.fingerprint()},
        {"server", serverRoot.fingerprint()},
        {"issuedAt", kNow},
        {"notAfter", kNow + kThreeDays},
    };
    const Bytes futureDer = cms::signJsonHybrid(futureBody, user);
    CHECK_THROWS(ContactCard::verify(futureDer));

    return 0;
}
