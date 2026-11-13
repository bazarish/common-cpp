// Bazarish project (c) 2026
#include "bazarish/Devices.hpp"

#include "bazarish/Hybrid.hpp"

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace bazarish;

namespace {

constexpr std::int64_t kNow = 1780000000;

}  // namespace

int main()
{
    const Identity root = Identity::generate();
    const DeviceKeys phone = DeviceKeys::generate();
    const DeviceKeys tablet = DeviceKeys::generate();

    {
        const std::string id = phone.id();
        CHECK(id.size() == kDeviceIdLength);
        CHECK(isDeviceId(id));
        CHECK(id
            == hybridFingerprint(
                phone.signing().classical().publicDer(), phone.signing().pq().publicDer())
                   .substr(0, kDeviceIdLength));
        CHECK(id == DevicePublic::of(phone).id());
        CHECK(id != tablet.id());
        const DeviceKeys reopened = DeviceKeys::fromPems(phone.signingPem(), phone.sealingPem());
        CHECK(reopened.id() == id);
        CHECK(reopened.sealing().publicDer() == phone.sealing().publicDer());
        CHECK(!isDeviceId("short"));
        CHECK(!isDeviceId("ABCDEFGHIJ"));
        CHECK(!isDeviceId("abcdefghi1"));
        CHECK(deviceKid(id).front() == kDeviceKidTag);
        CHECK(namesDevice(deviceKid(id)));
        CHECK(deviceKid(id).size() == 1 + kDeviceIdLength);
        CHECK_THROWS(deviceKid("not-an-id"));
        CHECK_THROWS(DeviceKeys::fromPems(phone.signingPem(), Key::generateX25519().privatePem()));
    }

    const Bytes phoneCert
        = DeviceCertificate::issue(root, DevicePublic::of(phone), DeviceRole::ePrimary, kNow);
    const Bytes tabletCert
        = DeviceCertificate::issue(root, DevicePublic::of(tablet), DeviceRole::eSecondary, kNow + 1);

    {
        const DeviceCertificate cert = DeviceCertificate::verify(phoneCert);
        CHECK(cert.root == root.fingerprint());
        CHECK(cert.device == phone.id());
        CHECK(cert.role == DeviceRole::ePrimary);
        CHECK(cert.issuedAt == kNow);
        CHECK(cert.signingClassicalDer == phone.signing().classical().publicDer());
        CHECK(cert.sealsWith(phone.sealing().publicDer()));
        CHECK(!cert.sealsWith(tablet.sealing().publicDer()));
        CHECK(DeviceCertificate::verify(tabletCert).role == DeviceRole::eSecondary);

        const Bytes data{'h', 'i'};
        cert.requireSigned(
            data, sign(phone.signing().classical(), data), sign(phone.signing().pq(), data));
        CHECK_THROWS(cert.requireSigned(
            data, sign(tablet.signing().classical(), data), sign(tablet.signing().pq(), data)));

        const DeviceCredential credential(Identity::fromPrivatePem(phone.signingPem()), phoneCert);
        CHECK(credential.device() == phone.id());
        CHECK(credential.account() == root.fingerprint());
        CHECK(credential.copy().certDer() == phoneCert);
        CHECK_THROWS(DeviceCredential(Identity::fromPrivatePem(tablet.signingPem()), phoneCert));
    }

    {
        const hybrid::VerifiedJson verified = hybrid::verifyJson(phoneCert);
        nlohmann::json body = verified.body;
        const Identity stranger = Identity::generate();
        CHECK_THROWS(DeviceCertificate::verify(hybrid::signJson(body, stranger)));
        CHECK_THROWS(DeviceCertificate::verify(hybrid::signJson(body, phone.signing())));
        nlohmann::json renamed = body;
        renamed["device"] = tablet.id();
        CHECK_THROWS(DeviceCertificate::verify(hybrid::signJson(renamed, root)));
        nlohmann::json promoted = hybrid::verifyJson(tabletCert).body;
        promoted["role"] = "owner";
        CHECK_THROWS(DeviceCertificate::verify(hybrid::signJson(promoted, root)));
        nlohmann::json extra = body;
        extra["note"] = "x";
        CHECK_THROWS(DeviceCertificate::verify(hybrid::signJson(extra, root)));
        for (const auto& [field, value] : body.items()) {
            nlohmann::json missing = body;
            missing.erase(field);
            CHECK_THROWS(DeviceCertificate::verify(hybrid::signJson(missing, root)));
        }
        CHECK(DeviceCertificate::verify(hybrid::signJson(body, root)).device == phone.id());
    }

    {
        const Bytes listed = RevocationList::issue(root, 2, {tablet.id(), phone.id(), tablet.id()}, kNow);
        const RevocationList list = RevocationList::verify(listed);
        CHECK(list.root == root.fingerprint());
        CHECK(list.number == 2);
        CHECK(list.revoked.size() == 2);
        CHECK(list.revokes(tablet.id()));
        CHECK(!list.revokes("aaaaaaaaaa"));
        CHECK_THROWS(RevocationList::issue(root, -1, {}, kNow));
        CHECK_THROWS(RevocationList::issue(root, 1, {"nope"}, kNow));
        nlohmann::json unordered = hybrid::verifyJson(listed).body;
        std::swap(unordered["revoked"][0], unordered["revoked"][1]);
        CHECK_THROWS(RevocationList::verify(hybrid::signJson(unordered, root)));
        CHECK_THROWS(RevocationList::verify(hybrid::signJson(hybrid::verifyJson(listed).body,
            Identity::generate())));
    }

    {
        const Bytes first = RevocationList::issue(root, kFirstRevocationNumber, {}, kNow);
        DeviceBook book;
        CHECK(book.empty());
        CHECK(book.take({phoneCert}, std::nullopt));
        CHECK(!book.complete());
        CHECK(book.root() == root.fingerprint());
        CHECK(book.take({tabletCert}, first));
        CHECK(book.complete());
        CHECK(!book.take({phoneCert, tabletCert}, first));
        CHECK(book.activeDevices().size() == 2);
        CHECK(book.activeDevices().front().device == phone.id());
        CHECK(book.active(tablet.id()).has_value());

        const Identity stranger = Identity::generate();
        const DeviceKeys stray = DeviceKeys::generate();
        CHECK_THROWS(book.take(
            {DeviceCertificate::issue(stranger, DevicePublic::of(stray), DeviceRole::ePrimary, kNow)},
            std::nullopt));
        CHECK_THROWS(book.take({}, RevocationList::issue(stranger, 1, {}, kNow)));
        CHECK(book.activeDevices().size() == 2);

        const Bytes second = RevocationList::issue(root, 1, {tablet.id()}, kNow);
        CHECK(book.take({}, second));
        CHECK(book.revoked(tablet.id()));
        CHECK(!book.active(tablet.id()).has_value());
        CHECK(book.revokedIds() == std::vector<std::string>{tablet.id()});
        CHECK(!book.take({tabletCert}, std::nullopt));
        CHECK(!book.active(tablet.id()).has_value());
        CHECK_THROWS(book.take({}, first));
        CHECK(book.revocationNumber() == 1);

        const DeviceBook stored = DeviceBook::fromJson(book.toJson());
        CHECK(stored == book);
        CHECK(stored.revoked(tablet.id()));
        CHECK(stored.activeCertDers() == std::vector<Bytes>{phoneCert});
    }

    return 0;
}
