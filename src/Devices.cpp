// Bazarish project (c) 2026
#include "bazarish/Devices.hpp"

#include "bazarish/Certificates.hpp"
#include "bazarish/Hybrid.hpp"

#include "SignedDocument.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <utility>

namespace bazarish {

namespace {

const char* const kDeviceCertType = "device-cert";
const char* const kDepartureType = "device-departure";
constexpr char kVersionField[] = "v";
constexpr char kTypeField[] = "t";
constexpr char kRootField[] = "root";
constexpr char kDeviceField[] = "device";
constexpr char kSigningField[] = "signing";
constexpr char kSealingField[] = "sealing";
constexpr char kRoleField[] = "role";
constexpr char kIssuedAtField[] = "issuedAt";
constexpr char kNumberField[] = "number";
constexpr char kRevokedField[] = "revoked";
constexpr char kClassicalKeyField[] = "c";
constexpr char kPqKeyField[] = "pq";
constexpr std::size_t kSigningKeyFields = 2;
constexpr char kCertsField[] = "certs";
constexpr char kRevocationField[] = "revocation";
constexpr char kPrimaryName[] = "primary";
constexpr char kSecondaryName[] = "secondary";

const std::set<std::string_view>& deviceCertFields()
{
    static const std::set<std::string_view> kFields{kVersionField, kTypeField, kRootField,
        kDeviceField, kSigningField, kSealingField, kRoleField, kIssuedAtField};
    return kFields;
}

const std::set<std::string_view>& departureFields()
{
    static const std::set<std::string_view> kFields{
        kVersionField, kTypeField, kRootField, kDeviceField, kIssuedAtField};
    return kFields;
}

const std::set<std::string_view>& revocationFields()
{
    static const std::set<std::string_view> kFields{kNumberField, kRevokedField};
    return kFields;
}

bool isBase32Char(const char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
}

void requireSigningPair(const Bytes& classicalDer, const Bytes& pqDer)
{
    if (!Key::fromPublicDer(classicalDer).isA(kClassicalSigningAlgorithm)
        || !Key::fromPublicDer(pqDer).isA(kPqSigningAlgorithm)) {
        throw std::runtime_error("a device signs with Ed25519 and ML-DSA-65");
    }
}

void requireSealingKey(const Bytes& sealingDer)
{
    const Key key = Key::fromPublicDer(sealingDer);
    if (!hybrid::isSealingKey(key)) {
        throw std::runtime_error("a device seals with X25519 and ML-KEM-768");
    }
}

std::tuple<std::int64_t, std::string> deviceOrder(const DeviceCertificate& cert)
{
    return {cert.issuedAt, cert.device};
}

}  // namespace

std::string_view deviceRoleName(const DeviceRole role)
{
    return role == DeviceRole::ePrimary ? kPrimaryName : kSecondaryName;
}

DeviceRole deviceRoleFromName(const std::string_view name)
{
    if (name == kPrimaryName) {
        return DeviceRole::ePrimary;
    }
    if (name == kSecondaryName) {
        return DeviceRole::eSecondary;
    }
    throw std::runtime_error("a device is primary or secondary, not " + std::string(name));
}

std::string deviceIdOf(const Bytes& signingClassicalDer, const Bytes& signingPqDer)
{
    return hybridFingerprint(signingClassicalDer, signingPqDer).substr(0, kDeviceIdLength);
}

bool isDeviceId(const std::string& text)
{
    return text.size() == kDeviceIdLength && std::all_of(text.begin(), text.end(), isBase32Char);
}

void requireDeviceId(const std::string& text)
{
    if (!isDeviceId(text)) {
        throw std::runtime_error("not a device id: " + text);
    }
}

Bytes deviceKid(const std::string& deviceId)
{
    requireDeviceId(deviceId);
    Bytes kid(sizeof(kDeviceKidTag) + deviceId.size());
    kid.front() = kDeviceKidTag;
    std::copy(deviceId.begin(), deviceId.end(), std::next(kid.begin()));
    return kid;
}

bool namesDevice(const Bytes& kid)
{
    return !kid.empty() && kid.front() == kDeviceKidTag;
}

DeviceKeys DeviceKeys::generate()
{
    return DeviceKeys(Identity::generate(), Key::generateSealing());
}

DeviceKeys DeviceKeys::fromPems(const std::string& signingPem, const std::string& sealingPem)
{
    Key sealing = Key::fromPrivatePem(sealingPem);
    requireSealingKey(sealing.publicDer());
    return DeviceKeys(Identity::fromPrivatePem(signingPem), std::move(sealing));
}

DeviceKeys::DeviceKeys(Identity signing, Key sealing)
    : signing_(std::move(signing))
    , sealing_(std::move(sealing))
{
}

const Identity& DeviceKeys::signing() const
{
    return signing_;
}

const Key& DeviceKeys::sealing() const
{
    return sealing_;
}

std::string DeviceKeys::id() const
{
    return deviceIdOf(signing_.classical().publicDer(), signing_.pq().publicDer());
}

std::string DeviceKeys::signingPem() const
{
    return signing_.privatePem();
}

std::string DeviceKeys::sealingPem() const
{
    return sealing_.privatePem();
}

std::string DevicePublic::id() const
{
    return deviceIdOf(signingClassicalDer, signingPqDer);
}

DevicePublic DevicePublic::of(const DeviceKeys& keys)
{
    return DevicePublic{keys.signing().classical().publicDer(), keys.signing().pq().publicDer(),
        keys.sealing().publicDer()};
}

Bytes DeviceCertificate::issue(const Identity& rootIdentity, const DevicePublic& device,
    const DeviceRole role, const std::int64_t issuedAt)
{
    requireSigningPair(device.signingClassicalDer, device.signingPqDer);
    requireSealingKey(device.sealingDer);
    const nlohmann::json body = {
        {kVersionField, kCertificateFormatVersion},
        {kTypeField, kDeviceCertType},
        {kRootField, rootIdentity.fingerprint()},
        {kDeviceField, device.id()},
        {kSigningField,
            {{kClassicalKeyField, toBase64(device.signingClassicalDer)},
                {kPqKeyField, toBase64(device.signingPqDer)}}},
        {kSealingField, toBase64(keyDigest(device.sealingDer))},
        {kRoleField, std::string(deviceRoleName(role))},
        {kIssuedAtField, issuedAt},
    };
    document::requireExactFields(body, deviceCertFields());
    return hybrid::signJson(body, rootIdentity);
}

DeviceCertificate DeviceCertificate::verify(const Bytes& der)
{
    const hybrid::VerifiedJson verified = document::verifyTagged(der, kDeviceCertType);
    document::requireExactFields(verified.body, deviceCertFields());
    DeviceCertificate cert;
    cert.root = verified.body.at(kRootField).get<std::string>();
    document::requireSigner(verified, cert.root);
    const nlohmann::json& signing = verified.body.at(kSigningField);
    if (!signing.is_object() || signing.size() != kSigningKeyFields) {
        throw std::runtime_error("a device certificate names exactly its two signing keys");
    }
    cert.signingClassicalDer = fromBase64(signing.at(kClassicalKeyField).get<std::string>());
    cert.signingPqDer = fromBase64(signing.at(kPqKeyField).get<std::string>());
    requireSigningPair(cert.signingClassicalDer, cert.signingPqDer);
    cert.device = verified.body.at(kDeviceField).get<std::string>();
    if (cert.device != deviceIdOf(cert.signingClassicalDer, cert.signingPqDer)) {
        throw std::runtime_error("a device certificate names a device its keys are not");
    }
    cert.sealingDigest = fromBase64(verified.body.at(kSealingField).get<std::string>());
    if (cert.sealingDigest.size() != kFingerprintBytes) {
        throw std::runtime_error("a device certificate names its sealing key by its digest");
    }
    cert.role = deviceRoleFromName(verified.body.at(kRoleField).get<std::string>());
    cert.issuedAt = verified.body.at(kIssuedAtField).get<std::int64_t>();
    return cert;
}

bool DeviceCertificate::sealsWith(const Bytes& sealingDer) const
{
    const Bytes digest = keyDigest(sealingDer);
    return digest.size() == sealingDigest.size()
        && CRYPTO_memcmp(digest.data(), sealingDigest.data(), digest.size()) == 0;
}

void DeviceCertificate::requireSigned(
    const Bytes& data, const Bytes& classicalSignature, const Bytes& pqSignature) const
{
    if (!bazarish::verify(Key::fromPublicDer(signingClassicalDer), data, classicalSignature)) {
        throw std::runtime_error("the device's classical signature does not verify");
    }
    if (!bazarish::verify(Key::fromPublicDer(signingPqDer), data, pqSignature)) {
        throw std::runtime_error("the device's post-quantum signature does not verify");
    }
}

Revocation Revocation::of(const std::int64_t number, std::vector<std::string> revoked)
{
    if (number < kFirstRevocationNumber) {
        throw std::invalid_argument("a revocation is numbered from zero");
    }
    for (const std::string& device : revoked) {
        requireDeviceId(device);
    }
    std::sort(revoked.begin(), revoked.end());
    revoked.erase(std::unique(revoked.begin(), revoked.end()), revoked.end());
    return Revocation{number, std::move(revoked)};
}

nlohmann::json Revocation::toJson() const
{
    return {{kNumberField, number}, {kRevokedField, revoked}};
}

Revocation Revocation::fromJson(const nlohmann::json& value)
{
    if (!value.is_object()) {
        throw std::runtime_error("a revocation is an object");
    }
    document::requireExactFields(value, revocationFields());
    Revocation revocation;
    revocation.number = value.at(kNumberField).get<std::int64_t>();
    if (revocation.number < kFirstRevocationNumber) {
        throw std::runtime_error("a revocation is numbered from zero");
    }
    revocation.revoked = value.at(kRevokedField).get<std::vector<std::string>>();
    for (std::size_t i = 0; i < revocation.revoked.size(); ++i) {
        requireDeviceId(revocation.revoked[i]);
        if (i > 0 && revocation.revoked[i - 1] >= revocation.revoked[i]) {
            throw std::runtime_error("a revocation names its devices in order, each once");
        }
    }
    return revocation;
}

bool Revocation::revokes(const std::string& device) const
{
    return std::binary_search(revoked.begin(), revoked.end(), device);
}

bool DeviceBook::empty() const
{
    return root_.empty();
}

const std::string& DeviceBook::root() const
{
    return root_;
}

const Revocation& DeviceBook::revocation() const
{
    return revocation_;
}

void DeviceBook::requireRoot(const std::string& root)
{
    if (root_.empty()) {
        root_ = root;
        return;
    }
    if (root != root_) {
        throw std::runtime_error("a device document of another account");
    }
}

bool DeviceBook::take(const std::vector<Bytes>& certDers, const std::optional<Revocation>& revocation)
{
    DeviceBook next = *this;
    bool learned = false;
    if (revocation.has_value()) {
        if (revocation->number < next.revocation_.number) {
            throw std::runtime_error("a revocation older than the one held");
        }
        if (revocation->number > next.revocation_.number) {
            learned = true;
            next.revocation_ = *revocation;
            std::erase_if(next.certs_,
                [&next](const auto& held) { return next.revocation_.revokes(held.first); });
            std::erase_if(next.certDers_,
                [&next](const auto& held) { return next.revocation_.revokes(held.first); });
        }
    }
    for (const Bytes& der : certDers) {
        DeviceCertificate cert = DeviceCertificate::verify(der);
        next.requireRoot(cert.root);
        if (next.revoked(cert.device) || next.certs_.contains(cert.device)) {
            continue;
        }
        next.certDers_[cert.device] = der;
        next.certs_.emplace(cert.device, std::move(cert));
        learned = true;
    }
    *this = std::move(next);
    return learned;
}

std::optional<DeviceCertificate> DeviceBook::active(const std::string& device) const
{
    const auto found = certs_.find(device);
    if (found == certs_.end()) {
        return std::nullopt;
    }
    return found->second;
}

bool DeviceBook::revoked(const std::string& device) const
{
    return revocation_.revokes(device);
}

std::vector<DeviceCertificate> DeviceBook::activeDevices() const
{
    std::vector<DeviceCertificate> devices;
    for (const auto& [id, cert] : certs_) {
        devices.push_back(cert);
    }
    std::sort(devices.begin(), devices.end(),
        [](const DeviceCertificate& a, const DeviceCertificate& b) {
            return deviceOrder(a) < deviceOrder(b);
        });
    return devices;
}

std::vector<Bytes> DeviceBook::activeCertDers() const
{
    std::vector<Bytes> ders;
    for (const DeviceCertificate& cert : activeDevices()) {
        ders.push_back(certDers_.at(cert.device));
    }
    return ders;
}

std::optional<Bytes> DeviceBook::certDer(const std::string& device) const
{
    const auto found = certDers_.find(device);
    if (found == certDers_.end()) {
        return std::nullopt;
    }
    return found->second;
}

nlohmann::json DeviceBook::toJson() const
{
    nlohmann::json certs = nlohmann::json::array();
    for (const Bytes& der : activeCertDers()) {
        certs.push_back(toBase64(der));
    }
    return {{kCertsField, certs}, {kRevocationField, revocation_.toJson()}};
}

DeviceBook DeviceBook::fromJson(const nlohmann::json& stored)
{
    std::vector<Bytes> certs;
    for (const nlohmann::json& cert : stored.at(kCertsField)) {
        certs.push_back(fromBase64(cert.get<std::string>()));
    }
    DeviceBook book;
    book.take(certs, Revocation::fromJson(stored.at(kRevocationField)));
    return book;
}

bool DeviceBook::operator==(const DeviceBook& other) const
{
    return root_ == other.root_ && certDers_ == other.certDers_ && revocation_ == other.revocation_;
}

DeviceCredential::DeviceCredential(Identity signing, Bytes certDer)
    : signing_(std::move(signing))
    , certDer_(std::move(certDer))
    , cert_(DeviceCertificate::verify(certDer_))
{
    if (cert_.signingClassicalDer != signing_.classical().publicDer()
        || cert_.signingPqDer != signing_.pq().publicDer()) {
        throw std::runtime_error("this device's certificate is for other keys");
    }
}

DeviceCredential DeviceCredential::copy() const
{
    return DeviceCredential(Identity::fromPrivatePem(signing_.privatePem()), certDer_);
}

const Identity& DeviceCredential::signing() const
{
    return signing_;
}

const Bytes& DeviceCredential::certDer() const
{
    return certDer_;
}

const DeviceCertificate& DeviceCredential::cert() const
{
    return cert_;
}

const std::string& DeviceCredential::device() const
{
    return cert_.device;
}

const std::string& DeviceCredential::account() const
{
    return cert_.root;
}

Bytes DeviceDeparture::issue(const DeviceCredential& device, const std::int64_t issuedAt)
{
    const nlohmann::json body = {
        {kVersionField, kCertificateFormatVersion},
        {kTypeField, kDepartureType},
        {kRootField, device.account()},
        {kDeviceField, device.device()},
        {kIssuedAtField, issuedAt},
    };
    document::requireExactFields(body, departureFields());
    return hybrid::signJson(body, device.signing());
}

DeviceDeparture DeviceDeparture::verify(const Bytes& der, const DeviceCertificate& cert)
{
    const hybrid::VerifiedJson verified = document::verifyTagged(der, kDepartureType);
    document::requireExactFields(verified.body, departureFields());
    if (verified.signerClassicalDer != cert.signingClassicalDer
        || verified.signerPqDer != cert.signingPqDer) {
        throw std::runtime_error("a departure signed by other keys than its device's");
    }
    DeviceDeparture departure;
    departure.root = verified.body.at(kRootField).get<std::string>();
    departure.device = verified.body.at(kDeviceField).get<std::string>();
    departure.issuedAt = verified.body.at(kIssuedAtField).get<std::int64_t>();
    if (departure.root != cert.root || departure.device != cert.device) {
        throw std::runtime_error("a departure names another device than the one that signed it");
    }
    return departure;
}

}  // namespace bazarish
