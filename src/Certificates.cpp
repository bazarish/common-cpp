// Bazarish project (c) 2026
#include "bazarish/Certificates.hpp"

#include "bazarish/Cms.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace {

using bazarish::cms::VerifiedHybridJson;

// Verifies the hybrid container and checks that the body claims the format
// version this implementation understands.
VerifiedHybridJson verifyVersioned(const bazarish::Bytes& der)
{
    VerifiedHybridJson verified = bazarish::cms::verifyJsonHybrid(der);
    if (verified.body.at("v").get<int>() != bazarish::kCertificateFormatVersion) {
        throw std::runtime_error("unsupported certificate format version");
    }
    return verified;
}

void requireSigner(const VerifiedHybridJson& verified, const std::string& expectedFingerprint)
{
    if (verified.identityFingerprint != expectedFingerprint) {
        throw std::runtime_error("certificate signer does not match the claimed identity");
    }
}

}  // namespace

namespace {

// What a contact card calls itself, so no other signed document can be read as
// one. Checked before any field of the body is used.
const char* const kContactCardType = "contact-card";

}  // namespace

namespace bazarish {

Bytes ContactCard::issue(const Identity& userIdentity, const std::int64_t issuedAt,
    const std::string& dest, const Bytes& sealingPublicKeyDer,
    const Bytes& servingSealingKeyDer)
{
    // No subject field: whoever signs this is its subject, and verify() reads
    // that from the signature.
    nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"t", kContactCardType},
        {"issuedAt", issuedAt},
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
    return cms::signJsonHybrid(body, userIdentity);
}

ContactCard ContactCard::verify(const Bytes& der)
{
    const VerifiedHybridJson verified = verifyVersioned(der);
    if (verified.body.value("t", std::string()) != kContactCardType) {
        throw std::runtime_error("this is not a contact card");
    }
    ContactCard card;
    // Required, unlike everything below it: a card that cannot be placed in time
    // cannot be compared with the one already held, which is the whole reason it
    // is here. Said in the protocol's own words rather than as a missing key.
    if (!verified.body.contains("issuedAt")) {
        throw std::runtime_error("a contact card must say when it was signed");
    }
    card.issuedAt = verified.body.at("issuedAt").get<std::int64_t>();
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

Bytes AliasCertificate::issue(const Identity& userIdentity, const std::string& alias,
    const std::int64_t issuedAt, const std::optional<std::int64_t> notAfter)
{
    nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"alias", alias},
        {"user", userIdentity.fingerprint()},
        {"issuedAt", issuedAt},
    };
    if (notAfter.has_value()) {
        body["notAfter"] = notAfter.value();
    }
    return cms::signJsonHybrid(body, userIdentity);
}

AliasCertificate AliasCertificate::verify(const Bytes& der)
{
    const VerifiedHybridJson verified = verifyVersioned(der);
    AliasCertificate cert;
    cert.v = verified.body.at("v").get<int>();
    cert.alias = verified.body.at("alias").get<std::string>();
    cert.user = verified.body.at("user").get<std::string>();
    cert.issuedAt = verified.body.at("issuedAt").get<std::int64_t>();
    if (verified.body.contains("notAfter")) {
        cert.notAfter = verified.body.at("notAfter").get<std::int64_t>();
    }
    requireSigner(verified, cert.user);
    return cert;
}

Bytes ServerCard::issue(const Identity& serverRootIdentity,
    const Key& sealingPublicKey,
    const std::int64_t issuedAt)
{
    const nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"server", serverRootIdentity.fingerprint()},
        {"sealingKey", toBase64(sealingPublicKey.publicDer())},
        {"issuedAt", issuedAt},
    };
    return cms::signJsonHybrid(body, serverRootIdentity);
}

ServerCard ServerCard::verify(const Bytes& der)
{
    const VerifiedHybridJson verified = verifyVersioned(der);
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
        {"root", rootIdentity.fingerprint()},
        {"delegatedClassical", toBase64(delegatedIdentity.classical().publicDer())},
        {"delegatedPq", toBase64(delegatedIdentity.pq().publicDer())},
        {"issuedAt", issuedAt},
        {"notAfter", notAfter},
    };
    return cms::signJsonHybrid(body, rootIdentity);
}

DelegationCertificate DelegationCertificate::verify(const Bytes& der)
{
    const VerifiedHybridJson verified = verifyVersioned(der);
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
