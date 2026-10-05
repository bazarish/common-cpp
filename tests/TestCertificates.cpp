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

    const Bytes bareDer = ContactCard::issue(user, kNow);
    const ContactCard bare = ContactCard::verify(bareDer);
    CHECK(bare.fingerprint() == user.fingerprint());
    CHECK(bare.dest.empty());
    CHECK(bare.sealingPublicKeyDer.empty());
    CHECK(bare.servingSealingKeyDer.empty());
    CHECK_THROWS(bare.sealingKey());
    CHECK_THROWS(bare.servingSealingKey());

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

    {
        const Identity impostor = Identity::generate();
        const nlohmann::json body = {{"v", kCertificateFormatVersion}, {"t", "contact-card"},
            {"issuedAt", kNow}, {"user", user.fingerprint()}};
        const ContactCard theirs = ContactCard::verify(cms::signJsonHybrid(body, impostor));
        CHECK(theirs.fingerprint() == impostor.fingerprint());
        CHECK(theirs.fingerprint() != user.fingerprint());
    }

    {
        const nlohmann::json notACard = {{"v", kCertificateFormatVersion}, {"t", "alias"},
            {"issuedAt", kNow}, {"alias", "someone"}};
        CHECK_THROWS(ContactCard::verify(cms::signJsonHybrid(notACard, user)));
        const nlohmann::json untagged = {{"v", kCertificateFormatVersion}};
        CHECK_THROWS(ContactCard::verify(cms::signJsonHybrid(untagged, user)));
    }

    {
        const nlohmann::json undated
            = {{"v", kCertificateFormatVersion}, {"t", "contact-card"}};
        CHECK_THROWS(ContactCard::verify(cms::signJsonHybrid(undated, user)));
    }

    {
        const Bytes olderDer = ContactCard::issue(user, kNow, "old.b32.i2p",
            sealing.publicDer(), servingSealing.publicDer());
        const Bytes newerDer = ContactCard::issue(user, kNow + 1, "new.b32.i2p",
            sealing.publicDer(), servingSealing.publicDer());
        CHECK(ContactCard::verify(olderDer).issuedAt
            < ContactCard::verify(newerDer).issuedAt);
    }

    const Bytes aliasDer = AliasCertificate::issue(user, "alice", kNow);
    const AliasCertificate alias = AliasCertificate::verify(aliasDer);
    CHECK(alias.alias == "alice");
    CHECK(alias.user == user.fingerprint());
    CHECK(alias.issuedAt == kNow);

    const Bytes cardDer = ServerCard::issue(serverRoot, sealing, kNow);
    const ServerCard card = ServerCard::verify(cardDer);
    CHECK(card.server == serverRoot.fingerprint());
    CHECK(card.issuedAt == kNow);
    CHECK(card.sealingKey().fingerprint() == sealing.fingerprint());

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

    {
        const nlohmann::json bothShapes = {
            {"v", kCertificateFormatVersion},
            {"t", "alias-certificate"},
            {"alias", "alice"},
            {"user", user.fingerprint()},
            {"server", user.fingerprint()},
            {"sealingKey", toBase64(sealing.publicDer())},
            {"issuedAt", kNow},
        };
        const Bytes bothDer = cms::signJsonHybrid(bothShapes, user);
        CHECK(AliasCertificate::verify(bothDer).alias == "alice");
        CHECK_THROWS(ServerCard::verify(bothDer));
        CHECK_THROWS(ContactCard::verify(bothDer));

        const nlohmann::json untaggedAlias = {{"v", kCertificateFormatVersion},
            {"alias", "alice"}, {"user", user.fingerprint()}, {"issuedAt", kNow}};
        CHECK_THROWS(AliasCertificate::verify(cms::signJsonHybrid(untaggedAlias, user)));
        const nlohmann::json untaggedServer = {{"v", kCertificateFormatVersion},
            {"server", user.fingerprint()}, {"sealingKey", toBase64(sealing.publicDer())},
            {"issuedAt", kNow}};
        CHECK_THROWS(ServerCard::verify(cms::signJsonHybrid(untaggedServer, user)));
        const nlohmann::json untaggedDelegation = {{"v", kCertificateFormatVersion},
            {"root", user.fingerprint()},
            {"delegatedClassical", toBase64(sealing.publicDer())},
            {"delegatedPq", toBase64(sealing.publicDer())}, {"issuedAt", kNow},
            {"notAfter", kNow + kThreeDays}};
        CHECK_THROWS(DelegationCertificate::verify(cms::signJsonHybrid(untaggedDelegation, user)));
    }

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
