// Bazarish project (c) 2026
#include "I2pKeys.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/I2pAddress.hpp>

// User-owned I2P key custody, now a thin shim over the shared bazarish::i2p::Keys
// (the embedded libi2pd in common) - the previously-vendored trimmed libi2pd
// "keys" lib is gone. The serialized blob is the i2pd-native PrivateKeys form;
// the base64 a server consumes is standard base64 of that blob (the server
// decodes it with fromBase64 + Keys::fromBlob).
namespace bazarish::client {

I2pMasterKey generateI2pMaster()
{
    // Minted locally rather than through the router, unlike every other
    // destination this client makes: the master is what delegation withholds
    // from whoever operates the address, so it must never leave this process.
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
