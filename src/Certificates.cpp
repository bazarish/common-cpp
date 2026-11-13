// Bazarish project (c) 2026
#include "bazarish/Certificates.hpp"

#include "bazarish/Hybrid.hpp"

#include "SignedDocument.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>

namespace {

using bazarish::hybrid::VerifiedJson;
using bazarish::document::requireExactFields;
using bazarish::document::requireSigner;
using bazarish::document::verifyTagged;

}  // namespace

namespace {

const char* const kContactCardType = "contact-card";
const char* const kAliasCertificateType = "alias-certificate";
const char* const kServerCardType = "server-card";
const char* const kNodeCardType = "node-card";
const char* const kDelegationCertificateType = "delegation-certificate";
constexpr char kVersionField[] = "v";
constexpr char kTypeField[] = "t";
constexpr char kIssuedAtField[] = "issuedAt";
constexpr char kKindField[] = "kind";
constexpr char kDestField[] = "dest";
constexpr char kEpochsField[] = "epochs";
constexpr char kServingKeyField[] = "servingKey";
constexpr char kDevicesField[] = "devices";
constexpr char kRevocationField[] = "revocation";

const std::set<std::string_view>& contactCardFields()
{
    static const std::set<std::string_view> kFields{kVersionField, kTypeField, kIssuedAtField,
        kKindField, kDestField, kEpochsField, kServingKeyField, kDevicesField, kRevocationField};
    return kFields;
}

void requireCardEpochs(
    const std::vector<bazarish::EpochPublic>& epochs, const bazarish::DeviceBook& devices)
{
    if (bazarish::chosenEpochs(epochs).size() != epochs.size() || epochs.size() != bazarish::kCardEpochs
        || epochs.back().n != epochs.front().n + 1) {
        throw std::runtime_error("a contact card carries an epoch and the one after it");
    }
    for (const bazarish::EpochPublic& epoch : epochs) {
        const std::optional<bazarish::DeviceCertificate> maker = devices.active(epoch.by);
        if (!maker.has_value() || maker->role != bazarish::DeviceRole::ePrimary) {
            throw std::runtime_error("a contact card carries an epoch key no primary device made");
        }
    }
}

bazarish::DeviceBook cardDevices(const std::vector<bazarish::Bytes>& certDers,
    const bazarish::Bytes& revocationDer)
{
    bazarish::DeviceBook devices;
    devices.take(certDers, revocationDer);
    if (devices.activeDevices().size() != certDers.size()) {
        throw std::runtime_error("a contact card lists each active device of its account once");
    }
    return devices;
}

std::vector<bazarish::Bytes> certsFromJson(const nlohmann::json& list)
{
    if (!list.is_array() || list.empty()) {
        throw std::runtime_error("a contact card lists the devices of its account");
    }
    std::vector<bazarish::Bytes> certs;
    for (const nlohmann::json& cert : list) {
        certs.push_back(bazarish::fromBase64(cert.get<std::string>()));
    }
    return certs;
}

std::string signingDevice(const bazarish::Bytes& classicalDer, const bazarish::Bytes& pqDer,
    const bazarish::DeviceBook& devices)
{
    const std::string id = bazarish::deviceIdOf(classicalDer, pqDer);
    const std::optional<bazarish::DeviceCertificate> signer = devices.active(id);
    if (!signer.has_value() || signer->signingClassicalDer != classicalDer
        || signer->signingPqDer != pqDer) {
        throw std::runtime_error("a contact card signed by none of its account's devices");
    }
    return id;
}

const char* cardType(const bazarish::ServerCard::Service service)
{
    return service == bazarish::ServerCard::Service::eServiceNode ? kNodeCardType
                                                                  : kServerCardType;
}

}  // namespace

namespace bazarish {

Bytes ContactCard::issue(const Identity& deviceSigning) const
{
    nlohmann::json certs = nlohmann::json::array();
    for (const Bytes& der : devices.activeCertDers()) {
        certs.push_back(toBase64(der));
    }
    const nlohmann::json body = {
        {kVersionField, kCertificateFormatVersion},
        {kTypeField, kContactCardType},
        {kIssuedAtField, issuedAt},
        {kKindField, std::string(accountKindName(kind))},
        {kDestField, dest},
        {kEpochsField, epochsJson(epochs)},
        {kServingKeyField, toBase64(servingSealingKeyDer)},
        {kDevicesField, certs},
        {kRevocationField, toBase64(devices.revocationDer())},
    };
    requireExactFields(body, contactCardFields());
    requireCardEpochs(epochs, devices);
    signingDevice(deviceSigning.classical().publicDer(), deviceSigning.pq().publicDer(), devices);
    return hybrid::signJson(body, deviceSigning);
}

ContactCard ContactCard::verify(const Bytes& der)
{
    const VerifiedJson verified = verifyTagged(der, kContactCardType);
    requireExactFields(verified.body, contactCardFields());
    ContactCard card;
    card.issuedAt = verified.body.at(kIssuedAtField).get<std::int64_t>();
    card.kind = accountKindFromName(verified.body.at(kKindField).get<std::string>());
    card.dest = verified.body.at(kDestField).get<std::string>();
    card.devices = cardDevices(certsFromJson(verified.body.at(kDevicesField)),
        fromBase64(verified.body.at(kRevocationField).get<std::string>()));
    card.signer = signingDevice(verified.signerClassicalDer, verified.signerPqDer, card.devices);
    card.epochs = epochsFromJson(verified.body.at(kEpochsField));
    requireCardEpochs(card.epochs, card.devices);
    card.servingSealingKeyDer = fromBase64(verified.body.at(kServingKeyField).get<std::string>());
    return card;
}

std::string ContactCard::fingerprint() const
{
    return devices.root();
}

Key ContactCard::servingSealingKey() const
{
    if (servingSealingKeyDer.empty()) {
        throw std::runtime_error("contact card carries no serving sealing key");
    }
    return Key::fromPublicDer(servingSealingKeyDer);
}

Bytes AliasCertificate::issue(
    const Identity& userIdentity, const std::string& alias, const std::int64_t issuedAt)
{
    const nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"t", kAliasCertificateType},
        {"alias", alias},
        {"user", userIdentity.fingerprint()},
        {"issuedAt", issuedAt},
    };
    return hybrid::signJson(body, userIdentity);
}

AliasCertificate AliasCertificate::verify(const Bytes& der)
{
    const VerifiedJson verified = verifyTagged(der, kAliasCertificateType);
    AliasCertificate cert;
    cert.alias = verified.body.at("alias").get<std::string>();
    cert.user = verified.body.at("user").get<std::string>();
    cert.issuedAt = verified.body.at("issuedAt").get<std::int64_t>();
    requireSigner(verified, cert.user);
    return cert;
}

Bytes ServerCard::issue(const Identity& serverRootIdentity, const Service service,
    const Key& sealingPublicKey, const std::int64_t issuedAt)
{
    const nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"t", cardType(service)},
        {"server", serverRootIdentity.fingerprint()},
        {"sealingKey", toBase64(sealingPublicKey.publicDer())},
        {"issuedAt", issuedAt},
    };
    return hybrid::signJson(body, serverRootIdentity);
}

ServerCard ServerCard::verify(const Bytes& der, const Service service)
{
    const VerifiedJson verified = verifyTagged(der, cardType(service));
    ServerCard card;
    card.server = verified.body.at("server").get<std::string>();
    card.sealingPublicKeyDer = fromBase64(verified.body.at("sealingKey").get<std::string>());
    card.issuedAt = verified.body.at("issuedAt").get<std::int64_t>();
    requireSigner(verified, card.server);
    return card;
}

Key ServerCard::sealingKey() const
{
    return Key::fromPublicDer(sealingPublicKeyDer);
}

Bytes DelegationCertificate::issue(const Identity& rootIdentity,
    const Identity& delegatedIdentity, const std::int64_t issuedAt, const std::int64_t notAfter)
{
    const nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"t", kDelegationCertificateType},
        {"root", rootIdentity.fingerprint()},
        {"delegatedClassical", toBase64(delegatedIdentity.classical().publicDer())},
        {"delegatedPq", toBase64(delegatedIdentity.pq().publicDer())},
        {"issuedAt", issuedAt},
        {"notAfter", notAfter},
    };
    return hybrid::signJson(body, rootIdentity);
}

DelegationCertificate DelegationCertificate::verify(const Bytes& der)
{
    const VerifiedJson verified = verifyTagged(der, kDelegationCertificateType);
    DelegationCertificate cert;
    cert.root = verified.body.at("root").get<std::string>();
    cert.delegatedClassicalPublicDer
        = fromBase64(verified.body.at("delegatedClassical").get<std::string>());
    cert.delegatedPqPublicDer = fromBase64(verified.body.at("delegatedPq").get<std::string>());
    cert.issuedAt = verified.body.at("issuedAt").get<std::int64_t>();
    cert.notAfter = verified.body.at("notAfter").get<std::int64_t>();
    requireSigner(verified, cert.root);
    return cert;
}

std::string DelegationCertificate::delegatedFingerprint() const
{
    return hybridFingerprint(delegatedClassicalPublicDer, delegatedPqPublicDer);
}

}  // namespace bazarish
