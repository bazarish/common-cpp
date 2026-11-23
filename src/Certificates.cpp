// Bazarish project (c) 2026
#include "bazarish/Certificates.hpp"

#include "bazarish/Hybrid.hpp"
#include "bazarish/I2pAddress.hpp"

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
constexpr char kRevocationField[] = "revocation";

const std::set<std::string_view>& contactCardFields()
{
    static const std::set<std::string_view> kFields{kVersionField, kTypeField, kIssuedAtField,
        kKindField, kDestField, kEpochsField, kServingKeyField, kRevocationField};
    return kFields;
}

void requireCardEpochs(
    const std::vector<bazarish::EpochPublic>& epochs, const bazarish::Revocation& revocation)
{
    if (bazarish::chosenEpochs(epochs).size() != epochs.size() || epochs.size() != bazarish::kCardEpochs
        || epochs.back().n != epochs.front().n + 1) {
        throw std::runtime_error("a contact card carries an epoch and the one after it");
    }
    for (const bazarish::EpochPublic& epoch : epochs) {
        if (epoch.g > revocation.number) {
            throw std::runtime_error("a contact card carries an epoch key of a revocation it does not hold");
        }
    }
}

const char* cardType(const bazarish::ServerCard::Service service)
{
    return service == bazarish::ServerCard::Service::eServerService ? kNodeCardType
                                                                  : kServerCardType;
}

}  // namespace

namespace bazarish {

Bytes ContactCard::issue(const Identity& root) const
{
    const nlohmann::json body = {
        {kVersionField, kCertificateFormatVersion},
        {kTypeField, kContactCardType},
        {kIssuedAtField, issuedAt},
        {kKindField, std::string(accountKindName(kind))},
        {kDestField, dest},
        {kEpochsField, epochsJson(epochs)},
        {kServingKeyField, toBase64(servingSealingKeyDer)},
        {kRevocationField, revocation.toJson()},
    };
    requireExactFields(body, contactCardFields());
    requireCardEpochs(epochs, revocation);
    return hybrid::signJson(body, root);
}

ContactCard ContactCard::verify(const Bytes& der)
{
    const VerifiedJson verified = verifyTagged(der, kContactCardType);
    requireExactFields(verified.body, contactCardFields());
    ContactCard card;
    card.issuedAt = verified.body.at(kIssuedAtField).get<std::int64_t>();
    card.kind = accountKindFromName(verified.body.at(kKindField).get<std::string>());
    card.dest = verified.body.at(kDestField).get<std::string>();
    validateB33I2pHost(card.dest);
    card.revocation = Revocation::fromJson(verified.body.at(kRevocationField));
    card.owner = hybridFingerprint(verified.signerClassicalDer, verified.signerPqDer);
    card.epochs = epochsFromJson(verified.body.at(kEpochsField));
    requireCardEpochs(card.epochs, card.revocation);
    card.servingSealingKeyDer = fromBase64(verified.body.at(kServingKeyField).get<std::string>());
    if (!hybrid::isSealingKey(Key::fromPublicDer(card.servingSealingKeyDer))) {
        throw std::runtime_error("a contact card names a serving key that is not X25519 and ML-KEM-768");
    }
    return card;
}

std::string ContactCard::fingerprint() const
{
    return owner;
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
    const Key& sealingPublicKey)
{
    const nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"t", cardType(service)},
        {"server", serverRootIdentity.fingerprint()},
        {"sealingKey", toBase64(sealingPublicKey.publicDer())},
    };
    return hybrid::signJson(body, serverRootIdentity);
}

ServerCard ServerCard::verify(const Bytes& der, const Service service)
{
    const VerifiedJson verified = verifyTagged(der, cardType(service));
    ServerCard card;
    card.server = verified.body.at("server").get<std::string>();
    card.sealingPublicKeyDer = fromBase64(verified.body.at("sealingKey").get<std::string>());
    requireSigner(verified, card.server);
    if (!hybrid::isSealingKey(Key::fromPublicDer(card.sealingPublicKeyDer))) {
        throw std::runtime_error("a server card names a sealing key that is not X25519 and ML-KEM-768");
    }
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
