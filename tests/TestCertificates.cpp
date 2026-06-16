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

    // Subscription certificate round trip.
    const Bytes subscriptionDer
        = SubscriptionCertificate::issue(user, serverRoot.fingerprint(), kNow, kNow + kThreeDays);
    const SubscriptionCertificate subscription = SubscriptionCertificate::verify(subscriptionDer);
    CHECK(subscription.v == kCertificateFormatVersion);
    CHECK(subscription.user == user.fingerprint());
    CHECK(subscription.server == serverRoot.fingerprint());
    CHECK(subscription.issuedAt == kNow);
    CHECK(subscription.notAfter == kNow + kThreeDays);
    CHECK(!subscription.isExpired(kNow));
    CHECK(!subscription.isExpired(kNow + kThreeDays));
    CHECK(subscription.isExpired(kNow + kThreeDays + 1));
    // No prekey published by default.
    CHECK(subscription.sealingPublicKeyDer.empty());

    // Subscription certificate carrying a sealing prekey: the signed key
    // survives the round trip and is usable.
    const Bytes prekeyDer
        = SubscriptionCertificate::issue(user, serverRoot.fingerprint(), kNow,
            kNow + kThreeDays, sealing.publicDer());
    const SubscriptionCertificate withPrekey = SubscriptionCertificate::verify(prekeyDer);
    CHECK(withPrekey.sealingPublicKeyDer == sealing.publicDer());
    CHECK(withPrekey.sealingKey().publicDer() == sealing.publicDer());
    // The destination-routed fields default empty when not published.
    CHECK(withPrekey.dest.empty());
    CHECK(withPrekey.servingSealingKeyDer.empty());
    CHECK_THROWS(withPrekey.servingSealingKey());

    // Destination-routed subscription certificate (see api/InviteAnonymity.md):
    // the user vouches for its serving destination and serving sealing key under
    // the same single signature; both survive the round trip and are usable.
    const Key servingSealing = Key::generateSealing();
    const std::string dest = "exampledestination.b32.i2p";
    const Bytes routedDer = SubscriptionCertificate::issue(user, serverRoot.fingerprint(), kNow,
        kNow + kThreeDays, sealing.publicDer(), dest, servingSealing.publicDer());
    const SubscriptionCertificate routed = SubscriptionCertificate::verify(routedDer);
    CHECK(routed.dest == dest);
    CHECK(routed.servingSealingKeyDer == servingSealing.publicDer());
    CHECK(routed.servingSealingKey().publicDer() == servingSealing.publicDer());
    // The prekey and the serving key are independent keys.
    CHECK(routed.sealingKey().publicDer() == sealing.publicDer());
    CHECK(routed.servingSealingKey().fingerprint() != routed.sealingKey().fingerprint());

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
    CHECK_THROWS(SubscriptionCertificate::verify(forgedDer));

    // An unsupported format version must be rejected.
    const nlohmann::json futureBody = {
        {"v", kCertificateFormatVersion + 1},
        {"user", user.fingerprint()},
        {"server", serverRoot.fingerprint()},
        {"issuedAt", kNow},
        {"notAfter", kNow + kThreeDays},
    };
    const Bytes futureDer = cms::signJsonHybrid(futureBody, user);
    CHECK_THROWS(SubscriptionCertificate::verify(futureDer));

    return 0;
}
