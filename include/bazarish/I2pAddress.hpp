// Bazarish project (c) 2026
#pragma once

#include <string>

namespace bazarish {

// Derives the shareable .b32.i2p host for a destination published as an
// ENCRYPTED LeaseSet2 — the blinded "b33" address (I2P proposals 123/149).
//
// This is NOT base32(sha256(destination)) (the standard-LeaseSet form): it is
// base32 of {flags, sigType, blindedSigType, signingPublicKey} with a CRC-32
// over the signing key XORed into the three-byte prefix, matching i2pd's
// BlindedPublicKey::ToB33. An encrypted-LeaseSet destination is reachable only
// via this b33; a connect to its raw destination fails (no plain leaseset is
// published), so this is what callers route to.
//
// The input is the SAM base64 destination (I2P-base64 alphabet). Only Ed25519
// (signature type 7) destinations are supported. Throws on a malformed or
// unsupported destination.
std::string encryptedLeaseSetHost(const std::string& samBase64Destination);

}  // namespace bazarish
