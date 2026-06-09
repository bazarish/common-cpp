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

namespace bazarish {

Bytes SubscriptionCertificate::issue(const Identity& userIdentity,
    const std::string& serverFingerprint, const std::int64_t issuedAt,
    const std::int64_t notAfter, const Bytes& sealingPublicKeyDer)
{
    nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"user", userIdentity.fingerprint()},
        {"server", serverFingerprint},
        {"issuedAt", issuedAt},
        {"notAfter", notAfter},
    };
    if (!sealingPublicKeyDer.empty()) {
        body["sealingKey"] = toBase64(sealingPublicKeyDer);
    }
    return cms::signJsonHybrid(body, userIdentity);
}

SubscriptionCertificate SubscriptionCertificate::verify(const Bytes& der)
{
    const VerifiedHybridJson verified = verifyVersioned(der);
    SubscriptionCertificate cert;
    cert.v = verified.body.at("v").get<int>();
    cert.user = verified.body.at("user").get<std::string>();
    cert.server = verified.body.at("server").get<std::string>();
    cert.issuedAt = verified.body.at("issuedAt").get<std::int64_t>();
    cert.notAfter = verified.body.at("notAfter").get<std::int64_t>();
    if (verified.body.contains("sealingKey")) {
        cert.sealingPublicKeyDer
            = fromBase64(verified.body.at("sealingKey").get<std::string>());
    }
    requireSigner(verified, cert.user);
    return cert;
}

Key SubscriptionCertificate::sealingKey() const
{
    if (sealingPublicKeyDer.empty()) {
        throw std::runtime_error("subscription certificate carries no sealing prekey");
    }
    return Key::fromPublicDer(sealingPublicKeyDer);
}

bool SubscriptionCertificate::isExpired(const std::int64_t now) const
{
    return now > notAfter;
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
    const std::vector<std::string>& endpoints, const Key& sealingPublicKey,
    const std::int64_t issuedAt)
{
    const nlohmann::json body = {
        {"v", kCertificateFormatVersion},
        {"server", serverRootIdentity.fingerprint()},
        {"endpoints", endpoints},
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
    card.endpoints = verified.body.at("endpoints").get<std::vector<std::string>>();
    card.sealingPublicKeyDer = fromBase64(verified.body.at("sealingKey").get<std::string>());
    card.issuedAt = verified.body.at("issuedAt").get<std::int64_t>();
    requireSigner(verified, card.server);
    return card;
}

Key ServerCard::sealingKey() const
{
    return Key::fromPublicDer(sealingPublicKeyDer);
}

}  // namespace bazarish
