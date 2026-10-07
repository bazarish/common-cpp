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

inline constexpr std::int64_t kClockSkewSeconds = 300;

struct ContactCard {
    std::string dest;
    Bytes sealingPublicKeyDer;
    std::int64_t issuedAt = 0;
    Bytes servingSealingKeyDer;
    // The identity keys that signed this card (SPKI DER).
    Bytes identityClassicalDer;
    Bytes identityPqDer;

    std::string fingerprint() const;

    static Bytes issue(const Identity& userIdentity, std::int64_t issuedAt,
        const std::string& dest = {}, const Bytes& sealingPublicKeyDer = {},
        const Bytes& servingSealingKeyDer = {});
    // Verifies both signatures and that the signer is body.user.
    static ContactCard verify(const Bytes& der);

    Key sealingKey() const;
    Key servingSealingKey() const;
};

struct AliasCertificate {
    int v = kCertificateFormatVersion;
    std::string alias;
    std::string user;
    std::int64_t issuedAt = 0;

    static Bytes issue(
        const Identity& userIdentity, const std::string& alias, std::int64_t issuedAt);
    // Verifies both signatures and that the signer is body.user.
    static AliasCertificate verify(const Bytes& der);
};

struct ServerCard {
    int v = kCertificateFormatVersion;
    std::string server;
    Bytes sealingPublicKeyDer;
    std::int64_t issuedAt = 0;

    static Bytes issue(const Identity& serverRootIdentity,
        const Key& sealingPublicKey, std::int64_t issuedAt);
    // Verifies both signatures and that the signer is body.server.
    static ServerCard verify(const Bytes& der);

    Key sealingKey() const;
};

struct DelegationCertificate {
    int v = kCertificateFormatVersion;
    std::string root;
    Bytes delegatedClassicalPublicDer;
    Bytes delegatedPqPublicDer;
    std::int64_t issuedAt = 0;
    std::int64_t notAfter = 0;

    static Bytes issue(const Identity& rootIdentity, const Identity& delegatedIdentity,
        std::int64_t issuedAt, std::int64_t notAfter);
    // Verifies both signatures and that the signer is body.root.
    static DelegationCertificate verify(const Bytes& der);

    std::string delegatedFingerprint() const;
};

}  // namespace bazarish
