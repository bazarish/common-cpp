// Bazarish project (c) 2026
#include "bazarish/Certificates.hpp"

#include "bazarish/Hybrid.hpp"

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

    const Key servingSealing = Key::generateSealing();
    const std::string dest = "exampledestination.b32.i2p";
    const auto cardOf = [&](const AccountKind kind) {
        ContactCard card;
        card.kind = kind;
        card.issuedAt = kNow;
        card.dest = dest;
        card.sealingPublicKeyDer = sealing.publicDer();
        card.servingSealingKeyDer = servingSealing.publicDer();
        return card;
    };
    const auto bodyOf = [&](const AccountKind kind) {
        return nlohmann::json{{"v", kCertificateFormatVersion}, {"t", "contact-card"},
            {"issuedAt", kNow}, {"kind", std::string(accountKindName(kind))}, {"dest", dest},
            {"sealingKey", toBase64(sealing.publicDer())},
            {"servingKey", toBase64(servingSealing.publicDer())}};
    };

    for (const AccountKind kind : {AccountKind::eUser, AccountKind::eBot, AccountKind::eChat}) {
        const ContactCard contact = ContactCard::verify(cardOf(kind).issue(user));
        CHECK(contact.kind == kind);
        CHECK(contact.fingerprint() == user.fingerprint());
        CHECK(contact.issuedAt == kNow);
        CHECK(contact.dest == dest);
        CHECK(contact.sealingKey().publicDer() == sealing.publicDer());
        CHECK(contact.servingSealingKey().publicDer() == servingSealing.publicDer());
        CHECK(ContactCard::verify(hybrid::signJson(bodyOf(kind), user)).kind == kind);

        const nlohmann::json complete = bodyOf(kind);
        for (const auto& [field, value] : complete.items()) {
            nlohmann::json missing = complete;
            missing.erase(field);
            CHECK_THROWS(ContactCard::verify(hybrid::signJson(missing, user)));
            if (value.is_string() && field != "t" && field != "kind") {
                nlohmann::json emptied = complete;
                emptied[field] = "";
                CHECK_THROWS(ContactCard::verify(hybrid::signJson(emptied, user)));
            }
        }
        nlohmann::json extraText = bodyOf(kind);
        extraText["note"] = "hello";
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(extraText, user)));
        nlohmann::json extraKey = bodyOf(kind);
        extraKey["key"] = toBase64(Key::generateX25519().publicDer());
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(extraKey, user)));
        nlohmann::json extraNull = bodyOf(kind);
        extraNull["empty"] = nullptr;
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(extraNull, user)));
        for (const int version : {0, kCertificateFormatVersion + 1}) {
            nlohmann::json versioned = bodyOf(kind);
            versioned["v"] = version;
            CHECK_THROWS(ContactCard::verify(hybrid::signJson(versioned, user)));
        }
        nlohmann::json textVersion = bodyOf(kind);
        textVersion["v"] = "1";
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(textVersion, user)));

        ContactCard noDest = cardOf(kind);
        noDest.dest.clear();
        CHECK_THROWS(noDest.issue(user));
        ContactCard noSealing = cardOf(kind);
        noSealing.sealingPublicKeyDer.clear();
        CHECK_THROWS(noSealing.issue(user));
        ContactCard noServing = cardOf(kind);
        noServing.servingSealingKeyDer.clear();
        CHECK_THROWS(noServing.issue(user));
    }
    const ContactCard full = cardOf(AccountKind::eUser);

    {
        nlohmann::json unknownKind = bodyOf(AccountKind::eUser);
        unknownKind["kind"] = "robot";
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(unknownKind, user)));
    }

    {
        const Identity impostor = Identity::generate();
        const ContactCard theirs = ContactCard::verify(full.issue(impostor));
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

    const Bytes cardDer
        = ServerCard::issue(serverRoot, ServerCard::Service::eMessaging, sealing, kNow);
    const ServerCard card = ServerCard::verify(cardDer, ServerCard::Service::eMessaging);
    CHECK(card.server == serverRoot.fingerprint());
    CHECK(card.issuedAt == kNow);
    CHECK(card.sealingKey().fingerprint() == sealing.fingerprint());
    CHECK_THROWS(ServerCard::verify(cardDer, ServerCard::Service::eServiceNode));
    const Bytes nodeCardDer
        = ServerCard::issue(serverRoot, ServerCard::Service::eServiceNode, sealing, kNow);
    CHECK(ServerCard::verify(nodeCardDer, ServerCard::Service::eServiceNode).server
        == serverRoot.fingerprint());
    CHECK_THROWS(ServerCard::verify(nodeCardDer, ServerCard::Service::eMessaging));

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
        CHECK_THROWS(ServerCard::verify(bothDer, ServerCard::Service::eMessaging));
        CHECK_THROWS(ContactCard::verify(bothDer));

        const nlohmann::json untaggedAlias = {{"v", kCertificateFormatVersion},
            {"alias", "alice"}, {"user", user.fingerprint()}, {"issuedAt", kNow}};
        CHECK_THROWS(AliasCertificate::verify(hybrid::signJson(untaggedAlias, user)));
        const nlohmann::json untaggedServer = {{"v", kCertificateFormatVersion},
            {"server", user.fingerprint()}, {"sealingKey", toBase64(sealing.publicDer())},
            {"issuedAt", kNow}};
        CHECK_THROWS(ServerCard::verify(
            hybrid::signJson(untaggedServer, user), ServerCard::Service::eMessaging));
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
