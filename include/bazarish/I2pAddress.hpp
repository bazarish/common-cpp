// Bazarish project (c) 2026
#pragma once

#include <string>

namespace bazarish {

// Derives the shareable .b32.i2p host for a destination published as an
// ENCRYPTED LeaseSet2 - the blinded "b33" address (I2P proposals 123/149).
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

// Derives the shareable .b32.i2p host for a destination published as a STANDARD
// LeaseSet2 - the ordinary base32(sha256(destination)) address (52 base32
// chars). This is the form for an offline-key per-user destination (and any
// standard-LeaseSet destination): it cannot publish a blinded b33, but it IS
// reachable by this standard b32. The input is the SAM base64 destination
// (I2P-base64 alphabet). Throws on a malformed destination.
std::string standardLeaseSetHost(const std::string& samBase64Destination);

// True iff host is a .b32.i2p address: it ends in ".b32.i2p" and the label is a
// non-empty lowercase RFC-4648 base32 string. The label LENGTH is not constrained
// - a standard b32 and a blinded b33 (and other signature types) legitimately
// differ in length. Short addressbook names (e.g. "name.i2p") and raw base64
// destinations are NOT valid. Project-wide invariant: every routing/connection
// target is a .b32.i2p host - no poisonable addressbook names, no raw destinations.
bool isB32I2pHost(const std::string& host);

// Throws std::invalid_argument unless isB32I2pHost(host). Call at every point an
// I2P address enters from outside (contact card, delivery envelope, config).
void validateB32I2pHost(const std::string& host);

}  // namespace bazarish
