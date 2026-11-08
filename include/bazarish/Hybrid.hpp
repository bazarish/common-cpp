// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace bazarish::hybrid {

inline constexpr int kFrameVersion = 1;

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

// One AEAD layer keyed from both shared secrets.
Bytes seal(const Bytes& plaintext, const Key& recipientPublicKey);
Bytes unseal(const Bytes& frame, const Key& recipientPrivateKey);

}  // namespace bazarish::hybrid
