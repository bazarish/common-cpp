// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>

namespace bazarish::cms {

// Signs a JSON document as CMS SignedData (DER).
Bytes signJson(const nlohmann::json& body, const Key& signingKey);

struct VerifiedJson {
    nlohmann::json body;
    std::string signerFingerprint;
    // SubjectPublicKeyInfo DER of the signer.
    Bytes signerPublicDer;
};

// Verifies the CMS signature against the embedded certificate and returns the payload.
VerifiedJson verifyJson(const Bytes& der);

Bytes signJsonHybrid(const nlohmann::json& body, const Identity& identity);

struct VerifiedHybridJson {
    nlohmann::json body;
    std::string identityFingerprint;
    // The keys that signed, as SubjectPublicKeyInfo DER.
    Bytes signerClassicalDer;
    Bytes signerPqDer;
};

VerifiedHybridJson verifyJsonHybrid(const Bytes& der);

// Hybrid envelope (encryption) to a sealing key.
Bytes seal(const Bytes& plaintext, const Key& recipientPublicKey);
Bytes unseal(const Bytes& der, const Key& recipientPrivateKey);

Bytes sealWithPassword(const Bytes& plaintext, const std::string& password);
Bytes unsealWithPassword(const Bytes& der, const std::string& password);

void sealWithPasswordToFile(const std::filesystem::path& inPath,
    const std::filesystem::path& outPath, const std::string& password);

void unsealWithPasswordToFile(const std::filesystem::path& derPath,
    const std::filesystem::path& outPath, const std::string& password);

}  // namespace bazarish::cms
