// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>
#include <bazarish/Devices.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::devicetest {

inline constexpr std::int64_t kIssuedAt = 1780000000;

// One device of an account, certified by the account's root.
struct Device {
    explicit Device(const Identity& root, const DeviceRole role = DeviceRole::ePrimary)
        : certDer(DeviceCertificate::issue(root, DevicePublic::of(keys), role, kIssuedAt))
        , credential(Identity::fromPrivatePem(keys.signingPem()), certDer)
    {
    }

    std::string id() const { return keys.id(); }

    DeviceKeys keys = DeviceKeys::generate();
    Bytes certDer;
    DeviceCredential credential;
};

// The devices of `root` as a card lists them, with the revocation list numbered `number`.
inline DeviceBook bookOf(const Identity& root, const std::vector<const Device*>& devices,
    const std::int64_t number = kFirstRevocationNumber, const std::vector<std::string>& revoked = {})
{
    std::vector<Bytes> certs;
    for (const Device* const device : devices) {
        certs.push_back(device->certDer);
    }
    DeviceBook book;
    book.take(certs, RevocationList::issue(root, number, revoked, kIssuedAt));
    return book;
}

// An account root and one primary device of it.
struct Account {
    Identity root = Identity::generate();
    Device primary{root};
    const DeviceKeys& keys = primary.keys;
    const Bytes& certDer = primary.certDer;
    const DeviceCredential& device = primary.credential;

    std::string fingerprint() const { return root.fingerprint(); }

    DeviceBook book() const { return bookOf(root, {&primary}); }
};

}  // namespace bazarish::devicetest
