// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace bazarish::cms {

// Signs a JSON document as CMS SignedData (DER). A self-signed X.509
// certificate wrapping the signer's public key is embedded so the receiver
// can verify the signature and derive the signer fingerprint with no other
// context. The certificate is a key carrier only; its own validity fields
// carry no meaning in the protocol.
Bytes signJson(const nlohmann::json& body, const Key& signingKey);

struct VerifiedJson {
    nlohmann::json body;
    // Fingerprint of the embedded signer public key. The caller decides
    // whether this fingerprint is the one it expects.
    std::string signerFingerprint;
    // SubjectPublicKeyInfo DER of the signer.
    Bytes signerPublicDer;
};

// Verifies the CMS signature against the embedded certificate and returns
// the payload. Throws on any structural or cryptographic failure.
VerifiedJson verifyJson(const Bytes& der);

// Hybrid post-quantum signing: the exact body bytes are signed with the
// identity's ML-DSA-65 key at the EVP level (OpenSSL CMS cannot carry
// ML-DSA signers), wrapped together with the public key and signature,
// and the wrapper is CMS-signed with the classical key. A statement is
// valid only when BOTH signatures verify.
//
// Wrapper layout (the CMS payload):
//   { "body": base64(bodyBytes),
//     "pq": { "alg": "ML-DSA-65", "pub": base64(SPKI), "sig": base64(sig) } }
Bytes signJsonHybrid(const nlohmann::json& body, const Identity& identity);

struct VerifiedHybridJson {
    nlohmann::json body;
    // The hybrid identity fingerprint covering both public keys.
    std::string identityFingerprint;
};

// Verifies both layers and the key types (an EC key smuggled into the pq
// slot is a downgrade and must fail). Throws on any failure.
VerifiedHybridJson verifyJsonHybrid(const Bytes& der);

// CMS envelope (encryption) to a sealing public key. Used for the sealed
// part of delivery envelopes and for sealed federation queries.
Bytes seal(const Bytes& plaintext, const Key& recipientPublicKey);
Bytes unseal(const Bytes& der, const Key& recipientPrivateKey);

}  // namespace bazarish::cms
