// Bazarish project (c) 2026
#include "bazarish/Certificates.hpp"

#include "bazarish/Hybrid.hpp"

#include <nlohmann/json.hpp>

#include <set>
#include <stdexcept>
#include <string_view>

namespace {

using bazarish::hybrid::VerifiedJson;

VerifiedJson verifyTagged(const bazarish::Bytes& der, const char* const type)
{
    VerifiedJson verified = bazarish::hybrid::verifyJson(der);
    if (verified.body.value("t", std::string()) != type) {
        throw std::runtime_error(std::string("wrong document type: expected ") + type);
    }
    if (verified.body.at("v").get<int>() != bazarish::kCertificateFormatVersion) {
        throw std::runtime_error("unsupported certificate format version");
    }
    return verified;
}

void requireSigner(const VerifiedJson& verified, const std::string& expectedFingerprint)
{
    if (verified.identityFingerprint != expectedFingerprint) {
        throw std::runtime_error("certificate signer does not match the claimed identity");
    }
}

void requireExactFields(const nlohmann::json& body, const std::set<std::string_view>& fields)
{
    if (!body.is_object() || body.size() != fields.size()) {
        throw std::runtime_error("a document must carry exactly the fields of its type");
    }
    for (const auto& [name, value] : body.items()) {
        if (!fields.contains(name)) {
            throw std::runtime_error("a document carries a field its type does not have: " + name);
        }
        if (value.is_string() && value.get_ref<const std::string&>().empty()) {
            throw std::runtime_error("a document carries an empty field: " + name);
        }
    }
}

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

const std::set<std::string_view>& contactCardFields()
{
    static const std::set<std::string_view> kFields{kVersionField, kTypeField, kIssuedAtField,
        kKindField, kDestField, kEpochsField, kServingKeyField};
    return kFields;
}

void requireCardEpochs(const std::vector<bazarish::EpochPublic>& epochs)
{
    if (bazarish::chosenEpochs(epochs).size() != epochs.size() || epochs.size() != bazarish::kCardEpochs
        || epochs.back().n != epochs.front().n + 1) {
        throw std::runtime_error("a contact card carries an epoch and the one after it");
    }
}

const char* cardType(const bazarish::ServerCard::Service service)
{
    return service == bazarish::ServerCard::Service::eServiceNode ? kNodeCardType
                                                                  : kServerCardType;
}

}  // namespace

namespace bazarish {

Bytes ContactCard::issue(const Identity& userIdentity) const
{
    const nlohmann::json body = {
        {kVersionField, kCertificateFormatVersion},
        {kTypeField, kContactCardType},
        {kIssuedAtField, issuedAt},
        {kKindField, std::string(accountKindName(kind))},
        {kDestField, dest},
        {kEpochsField, epochsJson(epochs)},
        {kServingKeyField, toBase64(servingSealingKeyDer)},
    };
    requireExactFields(body, contactCardFields());
    requireCardEpochs(epochs);
    return hybrid::signJson(body, userIdentity);
}

ContactCard ContactCard::verify(const Bytes& der)
{
    const VerifiedJson verified = verifyTagged(der, kContactCardType);
    requireExactFields(verified.body, contactCardFields());
    ContactCard card;
    card.issuedAt = verified.body.at(kIssuedAtField).get<std::int64_t>();
    card.kind = accountKindFromName(verified.body.at(kKindField).get<std::string>());
    card.dest = verified.body.at(kDestField).get<std::string>();
    card.epochs = epochsFromJson(verified.body.at(kEpochsField));
    requireCardEpochs(card.epochs);
    card.servingSealingKeyDer = fromBase64(verified.body.at(kServingKeyField).get<std::string>());
    card.identityClassicalDer = verified.signerClassicalDer;
    card.identityPqDer = verified.signerPqDer;
    return card;
}

std::string ContactCard::fingerprint() const
{
    return hybridFingerprint(identityClassicalDer, identityPqDer);
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
