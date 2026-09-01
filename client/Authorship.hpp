// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>

namespace bazarish::client {

// Who wrote a message, proved by the message itself.
//
// Nothing else in the path can answer that. A delivery token admits a
// correspondent - it says somebody the recipient issued tokens to put this in
// their mailbox - and the seal only says who may read it. The sender's own
// "from" field is a claim until something signs it, so every envelope carries
// the author's identity keys and both signatures over its content, hybrid like
// every other identity statement in this protocol.
//
// The block lives under this key inside the content, and is not part of what is
// signed: it is removed before the bytes are re-formed on either side.
inline constexpr const char* kAuthorshipField = "auth";

// What the block costs on the wire: 8224 bytes measured, the ML-DSA-65 public
// key and signature being nearly all of it (base64, inside the CBOR content).
// Stated here because every message pays it - a reaction and a read receipt as
// much as a letter - and because every size limit has to leave room for one.
inline constexpr std::size_t kAuthorshipBytes = 9216;

// Signs `content` in place. It must not already carry a block.
void signAuthorship(nlohmann::json& content, const Identity& identity);

// The fingerprint whose keys signed this content, taken as received (block
// included). Throws when there is no block, when a key is not of the two kinds
// this protocol signs with, or when either signature fails - a caller that
// cannot name the author must not show the message.
std::string authorOf(const nlohmann::json& content);

}  // namespace bazarish::client
