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
    const Bytes bareDer = ContactCard::issue(user);
    const ContactCard bare = ContactCard::verify(bareDer);
    CHECK(bare.v == kCertificateFormatVersion);
    CHECK(bare.user == user.fingerprint());
    CHECK(bare.dest.empty());
    CHECK(bare.sealingPublicKeyDer.empty());
    CHECK(bare.servingSealingKeyDer.empty());
    CHECK_THROWS(bare.sealingKey());
    CHECK_THROWS(bare.servingSealingKey());

    // A published card: routing and both keys ride under the one signature, and
    // nothing in it names the server that operates the destination.
    const Key servingSealing = Key::generateSealing();
    const std::string dest = "exampledestination.b32.i2p";
    const Bytes contactDer
        = ContactCard::issue(user, dest, sealing.publicDer(), servingSealing.publicDer());
    const ContactCard contact = ContactCard::verify(contactDer);
    CHECK(contact.user == user.fingerprint());
    CHECK(contact.dest == dest);
    CHECK(contact.sealingPublicKeyDer == sealing.publicDer());
    CHECK(contact.sealingKey().publicDer() == sealing.publicDer());
    CHECK(contact.servingSealingKeyDer == servingSealing.publicDer());
    CHECK(contact.servingSealingKey().publicDer() == servingSealing.publicDer());

    // A card signed by someone other than the user it names is refused.
    {
        const Identity impostor = Identity::generate();
        const nlohmann::json body
            = {{"v", kCertificateFormatVersion}, {"user", user.fingerprint()}};
        CHECK_THROWS(ContactCard::verify(cms::signJsonHybrid(body, impostor)));
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

    // Server card round trip.
    const std::vector<std::string> endpoints = {"i2p:exampledestination"};
    const Bytes cardDer = ServerCard::issue(serverRoot, endpoints, sealing, kNow);
    const ServerCard card = ServerCard::verify(cardDer);
    CHECK(card.server == serverRoot.fingerprint());
    CHECK(card.endpoints == endpoints);
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
