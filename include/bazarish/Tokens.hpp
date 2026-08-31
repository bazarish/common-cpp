// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <string>

namespace bazarish {

// One-time delivery tokens: 256 bits, and not simply random. Every token is
// minted under a mask that belongs to one correspondent, and carries a short
// mark under that mask. That is what makes a token revocable: the account that
// issued it can hand its own server the mask and have every token issued to that
// one correspondent dropped - without naming them, and without either side
// keeping a list of what was issued.
inline constexpr std::size_t kDeliveryTokenSize = 32;
// The account's static delivery secret: minted with the account, carried through
// export and import unchanged, and never sent anywhere.
inline constexpr std::size_t kDeliverySecretSize = 32;
// What a token says, under its mask, about which mask it was minted under.
inline constexpr char kDeliveryTokenMark[] = "SHIT";
inline constexpr std::size_t kDeliveryTokenMarkSize = 4;

// The mask for one correspondent: sha256(delivery secret || their fingerprint).
// It leaves the account only as a revocation request to the account's own server.
Bytes deliveryTokenMask(const Bytes& deliverySecret, const std::string& peerFingerprint);

// A fresh token under that mask: mask XOR (random || mark).
Bytes generateDeliveryToken(const Bytes& mask);

// Whether this token was minted under this mask - what a revocation sweep asks
// of every token it holds for one user. A token minted under another mask
// answers yes with probability 2^-32, and its holder loses one delivery.
bool deliveryTokenMatches(const Bytes& token, const Bytes& mask);

}  // namespace bazarish
