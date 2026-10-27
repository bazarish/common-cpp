// Bazarish project (c) 2026
#include "bazarish/Certificates.hpp"

#include "bazarish/Hybrid.hpp"

#include "TestUtil.hpp"

#include <stdexcept>

using namespace bazarish;

namespace {

constexpr std::int64_t kNow = 1780000000;
constexpr std::int64_t kThreeDays = 3 * 24 * 3600;
constexpr std::size_t kB33LabelLength = 56;

}  // namespace

int main()
{
    const Identity user = Identity::generate();
    const Identity serverRoot = Identity::generate();
    const Key sealing = Key::generateSealing();

    const Key presence = Key::generateX25519();
    const std::string presenceDest = std::string(kB33LabelLength, 'a') + ".b32.i2p";
    const auto userCard = [&]() {
        ContactCard card;
        card.issuedAt = kNow;
        card.presenceKeyDer = presence.publicDer();
        card.presenceDest = presenceDest;
        return card;
    };

    const ContactCard bare = ContactCard::verify(userCard().issue(user));
    CHECK(bare.fingerprint() == user.fingerprint());
    CHECK(bare.kind == AccountKind::eUser);
    CHECK(bare.dest.empty());
    CHECK(bare.sealingPublicKeyDer.empty());
    CHECK(bare.servingSealingKeyDer.empty());
    CHECK(bare.presenceKey().publicDer() == presence.publicDer());
    CHECK(bare.presenceDest == presenceDest);
    CHECK_THROWS(bare.sealingKey());
    CHECK_THROWS(bare.servingSealingKey());

    const Key servingSealing = Key::generateSealing();
    const std::string dest = "exampledestination.b32.i2p";
    ContactCard full = userCard();
    full.dest = dest;
    full.sealingPublicKeyDer = sealing.publicDer();
    full.servingSealingKeyDer = servingSealing.publicDer();
    const ContactCard contact = ContactCard::verify(full.issue(user));
    CHECK(contact.fingerprint() == user.fingerprint());
    CHECK(contact.issuedAt == kNow);
    CHECK(contact.dest == dest);
    CHECK(contact.sealingPublicKeyDer == sealing.publicDer());
    CHECK(contact.sealingKey().publicDer() == sealing.publicDer());
    CHECK(contact.servingSealingKeyDer == servingSealing.publicDer());
    CHECK(contact.servingSealingKey().publicDer() == servingSealing.publicDer());

    {
        ContactCard bot;
        bot.kind = AccountKind::eBot;
        bot.issuedAt = kNow;
        const ContactCard read = ContactCard::verify(bot.issue(user));
        CHECK(read.kind == AccountKind::eBot);
        CHECK(read.presenceKeyDer.empty());
        CHECK(read.presenceDest.empty());
        CHECK_THROWS(read.presenceKey());

        ContactCard chat = bot;
        chat.kind = AccountKind::eChat;
        CHECK(ContactCard::verify(chat.issue(user)).kind == AccountKind::eChat);

        ContactCard botWithPresence = userCard();
        botWithPresence.kind = AccountKind::eBot;
        CHECK_THROWS(botWithPresence.issue(user));

        ContactCard userWithoutPresence;
        userWithoutPresence.issuedAt = kNow;
        CHECK_THROWS(userWithoutPresence.issue(user));

        ContactCard userWithSealingPair = userCard();
        userWithSealingPair.presenceKeyDer = sealing.publicDer();
        CHECK_THROWS(userWithSealingPair.issue(user));

        ContactCard userWithBadAddress = userCard();
        userWithBadAddress.presenceDest = "not an address";
        CHECK_THROWS(userWithBadAddress.issue(user));
    }

    {
        const nlohmann::json kindless = {{"v", kCertificateFormatVersion}, {"t", "contact-card"},
            {"issuedAt", kNow}};
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(kindless, user)));
        const nlohmann::json unknownKind = {{"v", kCertificateFormatVersion},
            {"t", "contact-card"}, {"issuedAt", kNow}, {"kind", "robot"}};
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(unknownKind, user)));
        const nlohmann::json userWithoutPresence = {{"v", kCertificateFormatVersion},
            {"t", "contact-card"}, {"issuedAt", kNow}, {"kind", "user"}};
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(userWithoutPresence, user)));
        const nlohmann::json botWithPresence = {{"v", kCertificateFormatVersion},
            {"t", "contact-card"}, {"issuedAt", kNow}, {"kind", "bot"},
            {"presenceKey", toBase64(presence.publicDer())}, {"presenceDest", presenceDest}};
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(botWithPresence, user)));
    }

    {
        const Identity impostor = Identity::generate();
        const ContactCard theirs = ContactCard::verify(userCard().issue(impostor));
        CHECK(theirs.fingerprint() == impostor.fingerprint());
        CHECK(theirs.fingerprint() != user.fingerprint());
    }

    {
        const nlohmann::json notACard = {{"v", kCertificateFormatVersion}, {"t", "alias"},
            {"issuedAt", kNow}, {"alias", "someone"}};
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(notACard, user)));
        const nlohmann::json untagged = {{"v", kCertificateFormatVersion}};
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(untagged, user)));
    }

    {
        const nlohmann::json undated
            = {{"v", kCertificateFormatVersion}, {"t", "contact-card"}, {"kind", "bot"}};
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(undated, user)));
    }

    {
        ContactCard older = full;
        older.dest = "old.b32.i2p";
        ContactCard newer = full;
        newer.issuedAt = kNow + 1;
        newer.dest = "new.b32.i2p";
        CHECK(ContactCard::verify(older.issue(user)).issuedAt
            < ContactCard::verify(newer.issue(user)).issuedAt);
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
    const Bytes forgedDer = hybrid::signJson(forgedBody, mallory);
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
        const Bytes bothDer = hybrid::signJson(bothShapes, user);
        CHECK(AliasCertificate::verify(bothDer).alias == "alice");
        CHECK_THROWS(ServerCard::verify(bothDer));
        CHECK_THROWS(ContactCard::verify(bothDer));

        const nlohmann::json untaggedAlias = {{"v", kCertificateFormatVersion},
            {"alias", "alice"}, {"user", user.fingerprint()}, {"issuedAt", kNow}};
        CHECK_THROWS(AliasCertificate::verify(hybrid::signJson(untaggedAlias, user)));
        const nlohmann::json untaggedServer = {{"v", kCertificateFormatVersion},
            {"server", user.fingerprint()}, {"sealingKey", toBase64(sealing.publicDer())},
            {"issuedAt", kNow}};
        CHECK_THROWS(ServerCard::verify(hybrid::signJson(untaggedServer, user)));
        const nlohmann::json untaggedDelegation = {{"v", kCertificateFormatVersion},
            {"root", user.fingerprint()},
            {"delegatedClassical", toBase64(sealing.publicDer())},
            {"delegatedPq", toBase64(sealing.publicDer())}, {"issuedAt", kNow},
            {"notAfter", kNow + kThreeDays}};
        CHECK_THROWS(DelegationCertificate::verify(hybrid::signJson(untaggedDelegation, user)));
    }

    const nlohmann::json futureBody = {
        {"v", kCertificateFormatVersion + 1},
        {"user", user.fingerprint()},
        {"server", serverRoot.fingerprint()},
        {"issuedAt", kNow},
        {"notAfter", kNow + kThreeDays},
    };
    const Bytes futureDer = hybrid::signJson(futureBody, user);
    CHECK_THROWS(ContactCard::verify(futureDer));

    return 0;
}
