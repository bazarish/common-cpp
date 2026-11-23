// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bazarish {

enum class DeviceRole { ePrimary, eSecondary };

std::string_view deviceRoleName(DeviceRole role);
DeviceRole deviceRoleFromName(std::string_view name);

// Characters of the device's signing-key fingerprint that name it.
inline constexpr std::size_t kDeviceIdLength = 10;

std::string deviceIdOf(const Bytes& signingClassicalDer, const Bytes& signingPqDer);
bool isDeviceId(const std::string& text);
void requireDeviceId(const std::string& text);

inline constexpr std::uint8_t kDeviceKidTag = 0x02;
Bytes deviceKid(const std::string& deviceId);
bool namesDevice(const Bytes& kid);

inline constexpr std::int64_t kFirstRevocationNumber = 0;

// Kept on its device only.
class DeviceKeys {
public:
    static DeviceKeys generate();
    static DeviceKeys fromPems(const std::string& signingPem, const std::string& sealingPem);

    DeviceKeys(Identity signing, Key sealing);

    const Identity& signing() const;
    const Key& sealing() const;
    std::string id() const;
    std::string signingPem() const;
    std::string sealingPem() const;

private:
    Identity signing_;
    Key sealing_;
};

struct DevicePublic {
    // SPKI DER.
    Bytes signingClassicalDer;
    Bytes signingPqDer;
    Bytes sealingDer;

    std::string id() const;
    static DevicePublic of(const DeviceKeys& keys);
};

struct DeviceCertificate {
    std::string root;
    std::string device;
    // SPKI DER.
    Bytes signingClassicalDer;
    Bytes signingPqDer;
    // SHA-256 of the sealing key: contacts are not given the key itself.
    Bytes sealingDigest;
    DeviceRole role = DeviceRole::eSecondary;
    std::int64_t issuedAt = 0;

    static Bytes issue(const Identity& rootIdentity, const DevicePublic& device, DeviceRole role,
        std::int64_t issuedAt);
    static DeviceCertificate verify(const Bytes& der);

    bool sealsWith(const Bytes& sealingDer) const;
    // Throws unless both signatures over `data` verify under this device's keys.
    void requireSigned(const Bytes& data, const Bytes& classicalSignature,
        const Bytes& pqSignature) const;
};

struct Revocation {
    std::int64_t number = kFirstRevocationNumber;
    // Ascending, each once.
    std::vector<std::string> revoked;

    static Revocation of(std::int64_t number, std::vector<std::string> revoked);
    nlohmann::json toJson() const;
    static Revocation fromJson(const nlohmann::json& value);

    bool revokes(const std::string& device) const;
    bool operator==(const Revocation&) const = default;
};

// The devices of one account as another party holds them: certificates and the revocation.
class DeviceBook {
public:
    bool empty() const;
    const std::string& root() const;
    const Revocation& revocation() const;

    // Throws on another account's certificate or a lower revocation; true when it learned.
    bool take(const std::vector<Bytes>& certDers, const std::optional<Revocation>& revocation = {});

    std::optional<DeviceCertificate> active(const std::string& device) const;
    bool revoked(const std::string& device) const;
    // Oldest first.
    std::vector<DeviceCertificate> activeDevices() const;
    std::vector<Bytes> activeCertDers() const;
    std::optional<Bytes> certDer(const std::string& device) const;

    // {certs: [base64], revocation: {number, revoked}}.
    nlohmann::json toJson() const;
    static DeviceBook fromJson(const nlohmann::json& stored);

    bool operator==(const DeviceBook& other) const;

private:
    void requireRoot(const std::string& root);

    std::string root_;
    std::map<std::string, Bytes> certDers_;
    std::map<std::string, DeviceCertificate> certs_;
    Revocation revocation_;
};

class DeviceCredential {
public:
    DeviceCredential(Identity signing, Bytes certDer);

    DeviceCredential copy() const;

    const Identity& signing() const;
    const Bytes& certDer() const;
    const DeviceCertificate& cert() const;
    const std::string& device() const;
    const std::string& account() const;

private:
    Identity signing_;
    Bytes certDer_;
    DeviceCertificate cert_;
};

struct DeviceDeparture {
    std::string root;
    std::string device;
    std::int64_t issuedAt = 0;

    static Bytes issue(const DeviceCredential& device, std::int64_t issuedAt);
    // Throws unless the keys `cert` certifies signed it, for that device of that account.
    static DeviceDeparture verify(const Bytes& der, const DeviceCertificate& cert);
};

}  // namespace bazarish
