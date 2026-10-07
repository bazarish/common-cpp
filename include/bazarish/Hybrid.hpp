// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace bazarish::hybrid {

inline constexpr int kFrameVersion = 1;

// One CBOR frame carrying the body and both signatures over it.
Bytes signJson(const nlohmann::json& body, const Identity& identity);

struct VerifiedJson {
    nlohmann::json body;
    std::string identityFingerprint;
    // The keys that signed, as SubjectPublicKeyInfo DER.
    Bytes signerClassicalDer;
    Bytes signerPqDer;
};

// Throws unless both signatures verify under the key types they name.
VerifiedJson verifyJson(const Bytes& frame);

// One AEAD layer under a key derived from both shared secrets at once.
Bytes seal(const Bytes& plaintext, const Key& recipientPublicKey);
Bytes unseal(const Bytes& frame, const Key& recipientPrivateKey);

}  // namespace bazarish::hybrid
