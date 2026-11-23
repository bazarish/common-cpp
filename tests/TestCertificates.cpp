// Bazarish project (c) 2026
#include "bazarish/Certificates.hpp"

#include "bazarish/Hybrid.hpp"

#include "TestUtil.hpp"

#include <algorithm>
#include <stdexcept>

using namespace bazarish;

namespace {

constexpr std::int64_t kNow = 1780000000;
constexpr std::int64_t kThreeDays = 3 * 24 * 3600;
constexpr std::size_t kB33Label = 56;
constexpr std::size_t kB32Label = 52;

}  // namespace

int main()
try {
    const Identity user = Identity::generate();
    const DeviceKeys phone = DeviceKeys::generate();
    const DeviceKeys tablet = DeviceKeys::generate();
    const Identity& signer = user;
    const Identity serverRoot = Identity::generate();
    const Key sealing = Key::generateSealing();
    const Key nextSealing = Key::generateSealing();
    constexpr EpochNumber kEpoch = 10;
    const std::vector<EpochPublic> epochs{
        {kEpoch, kFirstEpochGeneration, phone.id(), sealing.publicDer()},
        {kEpoch + 1, kFirstEpochGeneration, phone.id(), nextSealing.publicDer()}};
    const Revocation revocation = Revocation::of(kFirstRevocationNumber, {});

    const Key servingSealing = Key::generateSealing();
    const std::string dest = std::string(kB33Label, 'a') + ".b32.i2p";
    const auto cardOf = [&](const AccountKind kind) {
        ContactCard card;
        card.kind = kind;
        card.issuedAt = kNow;
        card.dest = dest;
        card.epochs = epochs;
        card.servingSealingKeyDer = servingSealing.publicDer();
        card.revocation = revocation;
        return card;
    };
    const auto bodyOf = [&](const AccountKind kind) {
        return nlohmann::json{{"v", kCertificateFormatVersion}, {"t", "contact-card"},
            {"issuedAt", kNow}, {"kind", std::string(accountKindName(kind))}, {"dest", dest},
            {"epochs", epochsJson(epochs)},
            {"servingKey", toBase64(servingSealing.publicDer())},
            {"revocation", revocation.toJson()}};
    };

    for (const AccountKind kind : {AccountKind::eUser, AccountKind::eBot, AccountKind::eChat}) {
        const ContactCard contact = ContactCard::verify(cardOf(kind).issue(signer));
        CHECK(contact.kind == kind);
        CHECK(contact.fingerprint() == user.fingerprint());
        CHECK(contact.revocation == revocation);
        CHECK(contact.issuedAt == kNow);
        CHECK(contact.dest == dest);
        CHECK(contact.epochs == epochs);
        CHECK(contact.servingSealingKey().publicDer() == servingSealing.publicDer());
        CHECK(ContactCard::verify(hybrid::signJson(bodyOf(kind), signer)).kind == kind);

        const nlohmann::json complete = bodyOf(kind);
        for (const auto& [field, value] : complete.items()) {
            nlohmann::json missing = complete;
            missing.erase(field);
            CHECK_THROWS(ContactCard::verify(hybrid::signJson(missing, signer)));
            if (value.is_string() && field != "t" && field != "kind") {
                nlohmann::json emptied = complete;
                emptied[field] = "";
                CHECK_THROWS(ContactCard::verify(hybrid::signJson(emptied, signer)));
            }
        }
        nlohmann::json extraText = bodyOf(kind);
        extraText["note"] = "hello";
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(extraText, signer)));
        nlohmann::json extraKey = bodyOf(kind);
        extraKey["key"] = toBase64(Key::generateX25519().publicDer());
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(extraKey, signer)));
        nlohmann::json extraNull = bodyOf(kind);
        extraNull["empty"] = nullptr;
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(extraNull, signer)));
        nlohmann::json devices = bodyOf(kind);
        devices["devices"] = nlohmann::json::array();
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(devices, signer)));
        for (const int version : {0, kCertificateFormatVersion + 1}) {
            nlohmann::json versioned = bodyOf(kind);
            versioned["v"] = version;
            CHECK_THROWS(ContactCard::verify(hybrid::signJson(versioned, signer)));
        }
        nlohmann::json textVersion = bodyOf(kind);
        textVersion["v"] = "1";
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(textVersion, signer)));

        ContactCard noDest = cardOf(kind);
        noDest.dest.clear();
        CHECK_THROWS(noDest.issue(signer));
        ContactCard noSealing = cardOf(kind);
        noSealing.epochs.clear();
        CHECK_THROWS(noSealing.issue(signer));
        ContactCard oneEpoch = cardOf(kind);
        oneEpoch.epochs.pop_back();
        CHECK_THROWS(oneEpoch.issue(signer));
        ContactCard gap = cardOf(kind);
        gap.epochs.back().n = kEpoch + 2;
        CHECK_THROWS(gap.issue(signer));
        ContactCard sameEpoch = cardOf(kind);
        sameEpoch.epochs.back() = EpochPublic{kEpoch, kFirstEpochGeneration, tablet.id(), nextSealing.publicDer()};
        CHECK_THROWS(sameEpoch.issue(signer));

        nlohmann::json legacy = bodyOf(kind);
        legacy["sealingKey"] = toBase64(sealing.publicDer());
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(legacy, signer)));
        nlohmann::json three = bodyOf(kind);
        three["epochs"].push_back(epochsJson({{kEpoch + 2, kFirstEpochGeneration, phone.id(), sealing.publicDer()}}).at(0));
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(three, signer)));
        nlohmann::json wrongStart = bodyOf(kind);
        wrongStart["epochs"][0]["from"] = epochStart(kEpoch) + 1;
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(wrongStart, signer)));
        nlohmann::json extraEpochField = bodyOf(kind);
        extraEpochField["epochs"][0]["note"] = "x";
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(extraEpochField, signer)));
        nlohmann::json noMaker = bodyOf(kind);
        noMaker["epochs"][0].erase("by");
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(noMaker, signer)));
        nlohmann::json signingKey = bodyOf(kind);
        signingKey["epochs"][0]["key"] = toBase64(Key::generateSigning().publicDer());
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(signingKey, signer)));
        nlohmann::json backwards = bodyOf(kind);
        std::swap(backwards["epochs"][0], backwards["epochs"][1]);
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(backwards, signer)));
        ContactCard noServing = cardOf(kind);
        noServing.servingSealingKeyDer.clear();
        CHECK_THROWS(noServing.issue(signer));
    }
    const ContactCard full = cardOf(AccountKind::eUser);

    {
        nlohmann::json unknownKind = bodyOf(AccountKind::eUser);
        unknownKind["kind"] = "robot";
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(unknownKind, signer)));
    }

    {
        const Identity impostor = Identity::generate();
        CHECK(ContactCard::verify(full.issue(impostor)).fingerprint() == impostor.fingerprint());
        CHECK(ContactCard::verify(full.issue(phone.signing())).fingerprint() != user.fingerprint());

        nlohmann::json laterRevocation = bodyOf(AccountKind::eUser);
        laterRevocation["epochs"][1]["g"] = kFirstRevocationNumber + 1;
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(laterRevocation, signer)));
        nlohmann::json plainB32 = bodyOf(AccountKind::eUser);
        plainB32["dest"] = std::string(kB32Label, 'a') + ".b32.i2p";
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(plainB32, signer)));
        nlohmann::json weakServing = bodyOf(AccountKind::eUser);
        weakServing["servingKey"] = toBase64(Key::generateX25519().publicDer());
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(weakServing, signer)));

        ContactCard revoking = full;
        revoking.revocation = Revocation::of(kFirstRevocationNumber + 1, {tablet.id()});
        revoking.epochs.back().g = kFirstRevocationNumber + 1;
        const ContactCard revoked = ContactCard::verify(revoking.issue(signer));
        CHECK(revoked.revocation.revokes(tablet.id()));
        CHECK(!revoked.revocation.revokes(phone.id()));

        nlohmann::json backwardsList = bodyOf(AccountKind::eUser);
        backwardsList["revocation"] = {{"number", 1},
            {"revoked", {std::max(phone.id(), tablet.id()), std::min(phone.id(), tablet.id())}}};
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(backwardsList, signer)));
        nlohmann::json negative = bodyOf(AccountKind::eUser);
        negative["revocation"]["number"] = kFirstRevocationNumber - 1;
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(negative, signer)));
        nlohmann::json notAnId = bodyOf(AccountKind::eUser);
        notAnId["revocation"]["revoked"] = {"nope"};
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(notAnId, signer)));
        nlohmann::json extraRevocationField = bodyOf(AccountKind::eUser);
        extraRevocationField["revocation"]["issuedAt"] = kNow;
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(extraRevocationField, signer)));
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
        older.dest = std::string(kB33Label, 'o') + ".b32.i2p";
        ContactCard newer = full;
        newer.issuedAt = kNow + 1;
        newer.dest = std::string(kB33Label, 'n') + ".b32.i2p";
        CHECK(ContactCard::verify(older.issue(signer)).issuedAt
            < ContactCard::verify(newer.issue(signer)).issuedAt);
    }

    const Bytes aliasDer = AliasCertificate::issue(user, "alice", kNow);
    const AliasCertificate alias = AliasCertificate::verify(aliasDer);
    CHECK(alias.alias == "alice");
    CHECK(alias.user == user.fingerprint());
    CHECK(alias.issuedAt == kNow);

    const Bytes cardDer
        = ServerCard::issue(serverRoot, ServerCard::Service::eMessaging, sealing);
    const ServerCard card = ServerCard::verify(cardDer, ServerCard::Service::eMessaging);
    CHECK(card.server == serverRoot.fingerprint());
    CHECK(card.sealingKey().fingerprint() == sealing.fingerprint());
    CHECK_THROWS(ServerCard::verify(cardDer, ServerCard::Service::eServerService));
    const Bytes nodeCardDer
        = ServerCard::issue(serverRoot, ServerCard::Service::eServerService, sealing);
    CHECK(ServerCard::verify(nodeCardDer, ServerCard::Service::eServerService).server
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
} catch (...) {
    return testutil::failed();
}
