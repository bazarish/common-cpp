// Bazarish project (c) 2026
#include "I2pKeys.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/I2pAddress.hpp>

namespace bazarish::client {

I2pMasterKey generateI2pMaster()
{
    const bazarish::i2p::Keys keys = bazarish::i2p::Keys::generate();
    return {keys.blob(), bazarish::i2p::routingHost(keys.publicBase64())};
}

I2pMasterKey loadI2pMaster(const Bytes& privateKeysDat)
{
    const bazarish::i2p::Keys keys = bazarish::i2p::Keys::fromBlob(privateKeysDat);
    return {keys.blob(), bazarish::i2p::routingHost(keys.publicBase64())};
}

std::string i2pRoutingHost(const Bytes& privateKeys)
{
    return bazarish::i2p::routingHost(
        bazarish::i2p::Keys::fromBlob(privateKeys).publicBase64());
}

std::string i2pPrivateKeysBase64(const Bytes& privateKeys)
{
    // The serving server consumes this as standard base64 of the raw key blob.
    return toBase64(privateKeys);
}

Bytes issueI2pOfflineKeys(const Bytes& masterPrivateKeys, const int days)
{
    return bazarish::i2p::Keys::fromBlob(masterPrivateKeys).issueTransient(days).blob();
}

std::int64_t i2pDelegationExpires(const Bytes& privateKeys)
{
    return bazarish::i2p::Keys::fromBlob(privateKeys).transientExpires();
}

}  // namespace bazarish::client
