// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>

namespace bazarish::hybrid {

inline constexpr int kFrameVersion = 1;
// An epoch key id: tag, epoch, generation and the maker device's id.
inline constexpr std::size_t kMaxSealKidBytes = 19;

Bytes signJson(const nlohmann::json& body, const Identity& identity);

struct VerifiedJson {
    nlohmann::json body;
    std::string identityFingerprint;
    // SPKI DER.
    Bytes signerClassicalDer;
    Bytes signerPqDer;
};

// Throws unless both signatures verify.
VerifiedJson verifyJson(const Bytes& frame);

// One AEAD layer keyed from both shared secrets; `kid` names the recipient key and is bound in.
Bytes seal(const Bytes& plaintext, const Key& recipientPublicKey, const Bytes& kid);
Bytes sealedKid(const Bytes& frame);
Bytes unseal(const Bytes& frame, const Key& recipientPrivateKey);

}  // namespace bazarish::hybrid
