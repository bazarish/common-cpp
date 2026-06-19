// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <filesystem>
#include <memory>
#include <string>

typedef struct evp_pkey_st EVP_PKEY;

namespace bazarish {

// Size of a fingerprint source digest (SHA-256).
inline constexpr std::size_t kFingerprintBytes = 32;
// Text length of a fingerprint: base32 of 32 bytes, no padding.
inline constexpr std::size_t kFingerprintTextLength = 52;

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const;
};
using KeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

// A signing or sealing key. May hold only the public part.
class Key {
public:
    // Classical signing keys: ECDSA P-256. Ed25519 is not usable here -
    // OpenSSL CMS SignedData has no EdDSA support, and certificates are
    // CMS-signed by these keys.
    static Key generateSigning();
    // Post-quantum signing keys: ML-DSA-65 (FIPS 204). Not usable as a
    // CMS signer in OpenSSL, so the hybrid layering signs with it at the
    // EVP level (see Cms.hpp).
    static Key generateSigningPq();
    // Sealing keys for CMS envelopes: ECDH P-256 (X25519 recipients are
    // not supported by OpenSSL CMS). A distinct key from the identity key
    // by design, even though the curve is the same.
    static Key generateSealing();

    // When passphrase is non-empty the PEM is expected to be (or is written)
    // encrypted with AES-256-CBC; an empty passphrase keeps the historical
    // unencrypted form.
    static Key fromPrivatePem(const std::string& pem, const std::string& passphrase = {});
    static Key fromPublicDer(const Bytes& spkiDer);

    std::string privatePem(const std::string& passphrase = {}) const;
    // SubjectPublicKeyInfo DER - the canonical public form.
    Bytes publicDer() const;
    // base32(sha256(SubjectPublicKeyInfo DER)). Identifies a single key;
    // identities are identified by Identity::fingerprint() instead.
    std::string fingerprint() const;
    bool hasPrivate() const;
    // EVP algorithm match, e.g. isA("EC") or isA("ML-DSA-65").
    bool isA(const char* algorithmName) const;

    EVP_PKEY* raw() const;

private:
    friend class Identity;

    explicit Key(KeyPtr key, bool hasPrivate);

    KeyPtr key_;
    bool hasPrivate_;
};

// Signature over the data: ECDSA-SHA256 for EC keys (DER-encoded, variable
// length), pure ML-DSA for ML-DSA keys.
Bytes sign(const Key& key, const Bytes& data);
bool verify(const Key& key, const Bytes& data, const Bytes& signature);

Bytes sha256(const Bytes& data);

// Streaming SHA-256 of a file's contents, read in bounded chunks so a
// multi-gigabyte file is never held whole in memory. Throws if the file cannot
// be read.
Bytes sha256File(const std::filesystem::path& path);

// A hybrid post-quantum signing identity: ECDSA P-256 plus ML-DSA-65.
// Every identity-level statement carries both signatures and is valid only
// when both verify - forging requires breaking both schemes.
class Identity {
public:
    static Identity generate();
    // Reads two PEM blocks: the classical key first, the ML-DSA key second.
    // A non-empty passphrase decrypts both blocks (AES-256-CBC).
    static Identity fromPrivatePem(const std::string& pem, const std::string& passphrase = {});
    Identity(Key classical, Key pq);

    const Key& classical() const;
    const Key& pq() const;
    // Both private keys as two concatenated PEM blocks, encrypted with the
    // passphrase (AES-256-CBC) when it is non-empty.
    std::string privatePem(const std::string& passphrase = {}) const;
    // The canonical identity fingerprint, covering both public keys.
    std::string fingerprint() const;

private:
    Key classical_;
    Key pq_;
};

// base32(sha256(classical SPKI DER || ML-DSA SPKI DER)) - computable by
// verifiers holding only public material.
std::string hybridFingerprint(const Bytes& classicalPublicDer, const Bytes& pqPublicDer);

}  // namespace bazarish
