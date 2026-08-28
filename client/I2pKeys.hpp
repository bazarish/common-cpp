// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <string>

namespace bazarish::client {

// A user-owned I2P destination. The permanent ("master") private key is
// generated and held by the client and never leaves it; the stable base32
// address is the user's portable contact and routing identity, unchanged
// across serving servers.
struct I2pMasterKey {
    // Serialized i2pd PrivateKeys for the master destination. Persist this at
    // rest under the account passphrase - it is the user's long-term routing
    // identity, as sensitive as the messaging identity key.
    Bytes privateKeys;
    // The destination's base32 address, without the ".b32.i2p" suffix.
    std::string base32;
};

// Generates a fresh user-owned master I2P destination (Ed25519).
I2pMasterKey generateI2pMaster();

// Loads an existing user-owned master from an i2pd-native destination private
// key blob (the contents of a ".dat" the user already holds). It must be an
// unencrypted Ed25519 (signing type 7) destination - the only kind this project
// serves. Returns the master re-serialized into canonical form, with its stable
// base32. Throws if the blob is malformed, password-protected, or not Ed25519.
I2pMasterKey loadI2pMaster(const Bytes& privateKeysDat);

// The base32 address (without ".b32.i2p") of a serialized destination's
// private keys - master or offline. Throws on a malformed blob.
std::string i2pBase32(const Bytes& privateKeys);

// The I2P-base64 serialization of a destination's private keys - the form a
// server loads into its I2P router when it operates the destination from a
// delegated transient. Throws on a malformed blob.
std::string i2pPrivateKeysBase64(const Bytes& privateKeys);

// Issues time-boxed offline ("transient") keys from the master, valid until
// expiresUnix (unix seconds). The returned blob is handed to the serving
// server, which feeds it to its I2P router to operate the destination
// for the subscription window; the master stays on the client. The offline
// destination's base32 equals the master's, so the address is unchanged when
// the user moves to another server (a fresh transient is issued to the new
// operator, and the old operator is locked out once its transient expires).
// Throws on a malformed master.
Bytes issueI2pOfflineKeys(const Bytes& masterPrivateKeys, std::int64_t expiresUnix);

}  // namespace bazarish::client
