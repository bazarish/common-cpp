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
    const DeviceKeys phone = DeviceKeys::generate();
    const DeviceKeys tablet = DeviceKeys::generate();
    const Bytes phoneCert
        = DeviceCertificate::issue(user, DevicePublic::of(phone), DeviceRole::ePrimary, kNow);
    const Bytes tabletCert
        = DeviceCertificate::issue(user, DevicePublic::of(tablet), DeviceRole::eSecondary, kNow);
    const Bytes revocation = RevocationList::issue(user, kFirstRevocationNumber, {}, kNow);
    DeviceBook book;
    book.take({phoneCert, tabletCert}, revocation);
    const Identity& signer = phone.signing();
    const Identity serverRoot = Identity::generate();
    const Key sealing = Key::generateSealing();
    const Key nextSealing = Key::generateSealing();
    constexpr EpochNumber kEpoch = 10;
    const std::vector<EpochPublic> epochs{
        {kEpoch, kFirstEpochGeneration, phone.id(), sealing.publicDer()},
        {kEpoch + 1, kFirstEpochGeneration, phone.id(), nextSealing.publicDer()}};

    const Key servingSealing = Key::generateSealing();
    const std::string dest = "exampledestination.b32.i2p";
    const auto cardOf = [&](const AccountKind kind) {
        ContactCard card;
        card.kind = kind;
        card.issuedAt = kNow;
        card.dest = dest;
        card.epochs = epochs;
        card.servingSealingKeyDer = servingSealing.publicDer();
        card.devices = book;
        return card;
    };
    nlohmann::json listed = nlohmann::json::array();
    for (const Bytes& der : book.activeCertDers()) {
        listed.push_back(toBase64(der));
    }
    const auto bodyOf = [&](const AccountKind kind) {
        return nlohmann::json{{"v", kCertificateFormatVersion}, {"t", "contact-card"},
            {"issuedAt", kNow}, {"kind", std::string(accountKindName(kind))}, {"dest", dest},
            {"epochs", epochsJson(epochs)},
            {"servingKey", toBase64(servingSealing.publicDer())}, {"devices", listed},
            {"revocation", toBase64(revocation)}};
    };

    for (const AccountKind kind : {AccountKind::eUser, AccountKind::eBot, AccountKind::eChat}) {
        const ContactCard contact = ContactCard::verify(cardOf(kind).issue(signer));
        CHECK(contact.kind == kind);
        CHECK(contact.fingerprint() == user.fingerprint());
        CHECK(contact.signer == phone.id());
        CHECK(contact.devices == book);
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
        ContactCard twoMakers = cardOf(kind);
        twoMakers.epochs.back() = EpochPublic{kEpoch, kFirstEpochGeneration, tablet.id(), nextSealing.publicDer()};
        CHECK_THROWS(twoMakers.issue(signer));

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
        CHECK_THROWS(full.issue(impostor));
        CHECK_THROWS(full.issue(user));
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(bodyOf(AccountKind::eUser), impostor)));
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(bodyOf(AccountKind::eUser), user)));
        const ContactCard bySecondary = ContactCard::verify(full.issue(tablet.signing()));
        CHECK(bySecondary.signer == tablet.id());
        CHECK(bySecondary.fingerprint() == user.fingerprint());

        ContactCard secondaryKeys = full;
        secondaryKeys.epochs.back().by = tablet.id();
        CHECK_THROWS(secondaryKeys.issue(signer));
        nlohmann::json secondaryEpochs = bodyOf(AccountKind::eUser);
        secondaryEpochs["epochs"][1]["by"] = tablet.id();
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(secondaryEpochs, signer)));

        nlohmann::json revokedListed = bodyOf(AccountKind::eUser);
        revokedListed["revocation"]
            = toBase64(RevocationList::issue(user, kFirstRevocationNumber + 1, {tablet.id()}, kNow));
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(revokedListed, signer)));
        nlohmann::json twice = bodyOf(AccountKind::eUser);
        twice["devices"].push_back(twice["devices"][0]);
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(twice, signer)));
        nlohmann::json noDevices = bodyOf(AccountKind::eUser);
        noDevices["devices"] = nlohmann::json::array();
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(noDevices, signer)));

        const DeviceKeys strayKeys = DeviceKeys::generate();
        nlohmann::json foreign = bodyOf(AccountKind::eUser);
        foreign["devices"].push_back(toBase64(DeviceCertificate::issue(
            impostor, DevicePublic::of(strayKeys), DeviceRole::ePrimary, kNow)));
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(foreign, signer)));
        nlohmann::json foreignList = bodyOf(AccountKind::eUser);
        foreignList["revocation"]
            = toBase64(RevocationList::issue(impostor, kFirstRevocationNumber, {}, kNow));
        CHECK_THROWS(ContactCard::verify(hybrid::signJson(foreignList, signer)));
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
        CHECK(ContactCard::verify(older.issue(signer)).issuedAt
            < ContactCard::verify(newer.issue(signer)).issuedAt);
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
