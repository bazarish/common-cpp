// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bazarish {

inline constexpr int kCertificateFormatVersion = 1;

// All times are unix seconds, UTC.

// Subscription certificate: signed by the user, asserts "server S serves
// user U until T". The lifecycle anchor on the serving server and, pushed
// to contacts over E2E, the serving statement that answers "where do I
// deliver?". Expiry is policy, not validity: verify() does not reject
// expired certificates — callers decide (routing-staleness rule).
struct SubscriptionCertificate {
    int v = kCertificateFormatVersion;
    std::string user;
    std::string server;
    std::int64_t issuedAt = 0;
    std::int64_t notAfter = 0;
    // The user's sealing public key (SubjectPublicKeyInfo DER): a prekey,
    // signed by the user, that contacts use to E2E-encrypt the first
    // message before any token exchange. Empty when not published.
    Bytes sealingPublicKeyDer;

    static Bytes issue(const Identity& userIdentity, const std::string& serverFingerprint,
        std::int64_t issuedAt, std::int64_t notAfter, const Bytes& sealingPublicKeyDer = {});
    // Verifies the CMS signature and that the signer is body.user.
    static SubscriptionCertificate verify(const Bytes& der);

    // The sealing prekey as a usable Key. Throws when none was published.
    Key sealingKey() const;

    bool isExpired(std::int64_t now) const;
};

// Alias certificate: signed by the user, asserts "I am alias X".
struct AliasCertificate {
    int v = kCertificateFormatVersion;
    std::string alias;
    std::string user;
    std::int64_t issuedAt = 0;
    // Absent means unlimited (the default per server policy).
    std::optional<std::int64_t> notAfter;

    static Bytes issue(const Identity& userIdentity, const std::string& alias, std::int64_t issuedAt,
        std::optional<std::int64_t> notAfter);
    // Verifies the CMS signature and that the signer is body.user.
    static AliasCertificate verify(const Bytes& der);
};

// Server card: signed by the server root key; maps the server fingerprint
// to transport endpoints and the sealing key.
struct ServerCard {
    int v = kCertificateFormatVersion;
    std::string server;
    // Typed entries, e.g. "i2p:<destination>".
    std::vector<std::string> endpoints;
    // SubjectPublicKeyInfo DER of the sealing key.
    Bytes sealingPublicKeyDer;
    // Newer cards supersede older ones.
    std::int64_t issuedAt = 0;

    static Bytes issue(const Identity& serverRootIdentity, const std::vector<std::string>& endpoints,
        const Key& sealingPublicKey, std::int64_t issuedAt);
    // Verifies the CMS signature and that the signer is body.server.
    static ServerCard verify(const Bytes& der);

    Key sealingKey() const;
};

}  // namespace bazarish
