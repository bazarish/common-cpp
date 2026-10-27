// Bazarish project (c) 2026
#include "bazarish/Certificates.hpp"

#include "bazarish/Hybrid.hpp"
#include "bazarish/I2pAddress.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>

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

void requirePresenceFieldsMatch(const bazarish::ContactCard& card)
{
    const bool carriesKey = !card.presenceKeyDer.empty();
    const bool carriesDest = !card.presenceDest.empty();
    if (card.kind != bazarish::AccountKind::eUser) {
        if (carriesKey || carriesDest) {
            throw std::runtime_error("only a user card carries presence");
        }
        return;
    }
    if (!carriesKey || !carriesDest) {
        throw std::runtime_error("a user card must carry its presence key and address");
    }
    const bazarish::Key key = bazarish::Key::fromPublicDer(card.presenceKeyDer);
    if (key.hasKem() || !key.isA(bazarish::kClassicalSealingAlgorithm)) {
        throw std::runtime_error("a presence key is a bare X25519 key");
    }
    bazarish::validateB32I2pHost(card.presenceDest);
}

}  // namespace

namespace {

const char* const kContactCardType = "contact-card";
const char* const kAliasCertificateType = "alias-certificate";
const char* const kServerCardType = "server-card";
const char* const kDelegationCertificateType = "delegation-certificate";

}  // namespace

namespace bazarish {

Bytes ContactCard::issue(const Identity& userIdentity) const
{
    requirePresenceFieldsMatch(*this);
    nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"t", kContactCardType},
        {"issuedAt", issuedAt},
        {"kind", std::string(accountKindName(kind))},
    };
    if (!dest.empty()) {
        body["dest"] = dest;
    }
    if (!sealingPublicKeyDer.empty()) {
        body["sealingKey"] = toBase64(sealingPublicKeyDer);
    }
    if (!servingSealingKeyDer.empty()) {
        body["servingKey"] = toBase64(servingSealingKeyDer);
    }
    if (!presenceKeyDer.empty()) {
        body["presenceKey"] = toBase64(presenceKeyDer);
        body["presenceDest"] = presenceDest;
    }
    return hybrid::signJson(body, userIdentity);
}

ContactCard ContactCard::verify(const Bytes& der)
{
    const VerifiedJson verified = verifyTagged(der, kContactCardType);
    ContactCard card;
    if (!verified.body.contains("issuedAt")) {
        throw std::runtime_error("a contact card must say when it was signed");
    }
    card.issuedAt = verified.body.at("issuedAt").get<std::int64_t>();
    if (!verified.body.contains("kind")) {
        throw std::runtime_error("a contact card must say what kind of account it is");
    }
    card.kind = accountKindFromName(verified.body.at("kind").get<std::string>());
    if (verified.body.contains("presenceKey")) {
        card.presenceKeyDer = fromBase64(verified.body.at("presenceKey").get<std::string>());
    }
    if (verified.body.contains("presenceDest")) {
        card.presenceDest = verified.body.at("presenceDest").get<std::string>();
    }
    requirePresenceFieldsMatch(card);
    if (verified.body.contains("dest")) {
        card.dest = verified.body.at("dest").get<std::string>();
    }
    if (verified.body.contains("sealingKey")) {
        card.sealingPublicKeyDer = fromBase64(verified.body.at("sealingKey").get<std::string>());
    }
    if (verified.body.contains("servingKey")) {
        card.servingSealingKeyDer
            = fromBase64(verified.body.at("servingKey").get<std::string>());
    }
    card.identityClassicalDer = verified.signerClassicalDer;
    card.identityPqDer = verified.signerPqDer;
    return card;
}

std::string ContactCard::fingerprint() const
{
    return hybridFingerprint(identityClassicalDer, identityPqDer);
}

Key ContactCard::sealingKey() const
{
    if (sealingPublicKeyDer.empty()) {
        throw std::runtime_error("contact card carries no sealing prekey");
    }
    return Key::fromPublicDer(sealingPublicKeyDer);
}

Key ContactCard::servingSealingKey() const
{
    if (servingSealingKeyDer.empty()) {
        throw std::runtime_error("contact card carries no serving sealing key");
    }
    return Key::fromPublicDer(servingSealingKeyDer);
}

Key ContactCard::presenceKey() const
{
    if (presenceKeyDer.empty()) {
        throw std::runtime_error("contact card carries no presence key");
    }
    return Key::fromPublicDer(presenceKeyDer);
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
    cert.v = verified.body.at("v").get<int>();
    cert.alias = verified.body.at("alias").get<std::string>();
    cert.user = verified.body.at("user").get<std::string>();
    cert.issuedAt = verified.body.at("issuedAt").get<std::int64_t>();
    requireSigner(verified, cert.user);
    return cert;
}

Bytes ServerCard::issue(const Identity& serverRootIdentity,
    const Key& sealingPublicKey,
    const std::int64_t issuedAt)
{
    const nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"t", kServerCardType},
        {"server", serverRootIdentity.fingerprint()},
        {"sealingKey", toBase64(sealingPublicKey.publicDer())},
        {"issuedAt", issuedAt},
    };
    return hybrid::signJson(body, serverRootIdentity);
}

ServerCard ServerCard::verify(const Bytes& der)
{
    const VerifiedJson verified = verifyTagged(der, kServerCardType);
    ServerCard card;
    card.v = verified.body.at("v").get<int>();
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
    cert.v = verified.body.at("v").get<int>();
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
