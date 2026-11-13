// Bazarish project (c) 2026
#pragma once

#include "bazarish/AccountKind.hpp"
#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/Devices.hpp"
#include "bazarish/Epochs.hpp"

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
    // The current epoch and the next.
    std::vector<EpochPublic> epochs;
    std::int64_t issuedAt = 0;
    Bytes servingSealingKeyDer;
    // The account's active devices and its newest revocation list, each signed by its root.
    DeviceBook devices;
    // The device that signed the card.
    std::string signer;

    std::string fingerprint() const;

    Bytes issue(const Identity& deviceSigning) const;
    static ContactCard verify(const Bytes& der);

    Key servingSealingKey() const;
};

struct AliasCertificate {
    std::string alias;
    std::string user;
    std::int64_t issuedAt = 0;

    static Bytes issue(
        const Identity& userIdentity, const std::string& alias, std::int64_t issuedAt);
    static AliasCertificate verify(const Bytes& der);
};

struct ServerCard {
    enum class Service { eMessaging, eServiceNode };

    std::string server;
    Bytes sealingPublicKeyDer;
    std::int64_t issuedAt = 0;

    static Bytes issue(const Identity& serverRootIdentity, Service service,
        const Key& sealingPublicKey, std::int64_t issuedAt);
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
    static DelegationCertificate verify(const Bytes& der);

    std::string delegatedFingerprint() const;
};

}  // namespace bazarish
