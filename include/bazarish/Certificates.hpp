// Bazarish project (c) 2026
#pragma once

#include "bazarish/AccountKind.hpp"
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
    AccountKind kind = AccountKind::eUser;
    std::string dest;
    Bytes sealingPublicKeyDer;
    std::int64_t issuedAt = 0;
    Bytes servingSealingKeyDer;
    // Only a user card carries these two; a bot or chat card carries neither.
    Bytes presenceKeyDer;
    std::string presenceDest;
    // The identity keys that signed this card (SPKI DER).
    Bytes identityClassicalDer;
    Bytes identityPqDer;

    std::string fingerprint() const;

    Bytes issue(const Identity& userIdentity) const;
    static ContactCard verify(const Bytes& der);

    Key sealingKey() const;
    Key servingSealingKey() const;
    Key presenceKey() const;
};

struct AliasCertificate {
    std::string alias;
    std::string user;
    std::int64_t issuedAt = 0;

    static Bytes issue(
        const Identity& userIdentity, const std::string& alias, std::int64_t issuedAt);
    // Verifies both signatures and that the signer is body.user.
    static AliasCertificate verify(const Bytes& der);
};

struct ServerCard {
    // A facade carries a tunnel to each, and each opens it under its own sealing key.
    enum class Service { eMessaging, eServiceNode };

    std::string server;
    Bytes sealingPublicKeyDer;
    std::int64_t issuedAt = 0;

    static Bytes issue(const Identity& serverRootIdentity, Service service,
        const Key& sealingPublicKey, std::int64_t issuedAt);
    // Verifies both signatures, that the card is that service's and that the signer is body.server.
    static ServerCard verify(const Bytes& der, Service service);

    Key sealingKey() const;
};

struct DelegationCertificate {
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
