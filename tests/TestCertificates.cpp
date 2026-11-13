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
    const Key nextSealing = Key::generateSealing();
    constexpr EpochNumber kEpoch = 10;
    const std::vector<EpochPublic> epochs{
        {kEpoch, kFirstEpochGeneration, "dev1", sealing.publicDer()},
        {kEpoch + 1, kFirstEpochGeneration, "dev1", nextSealing.publicDer()}};

    const Key servingSealing = Key::generateSealing();
    const std::string dest = "exampledestination.b32.i2p";
    const auto cardOf = [&](const AccountKind kind) {
        ContactCard card;
        card.kind = kind;
        card.issuedAt = kNow;
        card.dest = dest;
        card.epochs = epochs;
        card.servingSealingKeyDer = servingSealing.publicDer();
        return card;
    };
    const auto bodyOf = [&](const AccountKind kind) {
        return nlohmann::json{{"v", kCertificateFormatVersion}, {"t", "contact-card"},
            {"issuedAt", kNow}, {"kind", std::string(accountKindName(kind))}, {"dest", dest},
            {"epochs", epochsJson(epochs)},
            {"servingKey", toBase64(servingSealing.publicDer())}};
    };

    for (const AccountKind kind : {AccountKind::eUser, AccountKind::eBot, AccountKind::eChat}) {
        const ContactCard contact = ContactCard::verify(cardOf(kind).issue(user));
        CHECK(contact.kind == kind);
        CHECK(contact.fingerprint() == user.fingerprint());
        CHECK(contact.issuedAt == kNow);
        CHECK(contact.dest == dest);
        CHECK(contact.epochs == epochs);
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
        noSealing.epochs.clear();
        CHECK_THROWS(noSealing.issue(user));
        ContactCard oneEpoch = cardOf(kind);
        oneEpoch.epochs.pop_back();
        CHECK_THROWS(oneEpoch.issue(user));
        ContactCard gap = cardOf(kind);
        gap.epochs.back().n = kEpoch + 2;
        CHECK_THROWS(gap.issue(user));
        ContactCard twoMakers = cardOf(kind);
        twoMakers.epochs.back() = EpochPublic{kEpoch, kFirstEpochGeneration, "dev2", nextSealing.publicDer()};
        CHECK_THROWS(twoMakers.issue(user));

        nlohmann::json legacy = bodyOf(kind);
        legacy["sealingKey"] = toBase64(sealing.publicDer());
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(legacy, user)));
        nlohmann::json three = bodyOf(kind);
        three["epochs"].push_back(epochsJson({{kEpoch + 2, kFirstEpochGeneration, "dev1", sealing.publicDer()}}).at(0));
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(three, user)));
        nlohmann::json wrongStart = bodyOf(kind);
        wrongStart["epochs"][0]["from"] = epochStart(kEpoch) + 1;
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(wrongStart, user)));
        nlohmann::json extraEpochField = bodyOf(kind);
        extraEpochField["epochs"][0]["note"] = "x";
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(extraEpochField, user)));
        nlohmann::json noMaker = bodyOf(kind);
        noMaker["epochs"][0].erase("by");
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(noMaker, user)));
        nlohmann::json signingKey = bodyOf(kind);
        signingKey["epochs"][0]["key"] = toBase64(Key::generateSigning().publicDer());
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(signingKey, user)));
        nlohmann::json backwards = bodyOf(kind);
        std::swap(backwards["epochs"][0], backwards["epochs"][1]);
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(backwards, user)));
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
