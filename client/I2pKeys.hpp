// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <string>

namespace bazarish::client {

struct I2pMasterKey {
    // Serialized i2pd PrivateKeys for the master destination.
    Bytes privateKeys;
    std::string host;
};

I2pMasterKey generateI2pMaster();

I2pMasterKey loadI2pMaster(const Bytes& privateKeysDat);

std::string i2pRoutingHost(const Bytes& privateKeys);

std::string i2pPrivateKeysBase64(const Bytes& privateKeys);

Bytes issueI2pOfflineKeys(const Bytes& masterPrivateKeys, int days);

std::int64_t i2pDelegationExpires(const Bytes& privateKeys);

}  // namespace bazarish::client
