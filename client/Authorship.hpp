// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
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
// both signatures over its content, hybrid like every other identity statement
// in this protocol.
//
// The block lives under this key inside the content and is not part of what is
// signed: it is removed before the bytes are re-formed on either side.
inline constexpr const char* kAuthorshipField = "auth";

// The keys an author signs with, as SubjectPublicKeyInfo DER.
struct IdentityKeys {
    Bytes classicalDer;
    Bytes pqDer;

    bool empty() const { return classicalDer.empty() || pqDer.empty(); }
};

// What the block costs on the wire, measured: 3396 bytes for the two signatures,
// 5471 with the keys as well. Stated here because every message pays the first
// figure and every size limit has to leave room for the second.
inline constexpr std::size_t kAuthorshipBytes = 5120;
inline constexpr std::size_t kAuthorshipWithKeysBytes = 8192;

// Signs `content` in place. The keys are included only where the reader may not
// have them yet - a contact request, and any message carrying a bootstrap -
// because they are a quarter of the block and a correspondent needs them once.
void signAuthorship(nlohmann::json& content, const Identity& identity, bool withKeys);

// The keys the block carries, or an empty pair when it carries none.
IdentityKeys keysIn(const nlohmann::json& content);

// The fingerprint whose keys signed this content, taken as received (block
// included). A block that carries no keys is verified against `known`, which is
// what the reader stored for the sender it claims to be. Throws when there is no
// block, when there are no keys to verify against, when a key is not of the two
// kinds this protocol signs with, or when either signature fails - a reader that
// cannot name the author must not show the message.
std::string authorOf(const nlohmann::json& content, const IdentityKeys& known = {});

}  // namespace bazarish::client
