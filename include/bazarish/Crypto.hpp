// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>

typedef struct evp_pkey_st EVP_PKEY;

namespace bazarish {

inline constexpr std::size_t kFingerprintBytes = 32;
// Text length of a fingerprint: base32 of 32 bytes, no padding.
inline constexpr std::size_t kFingerprintTextLength = 52;

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const;
};
using KeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

class Key {
public:
    static Key generateSigning();
    static Key generateSigningPq();
    static Key generateSealing();

    static Key fromPrivatePem(const std::string& pem, const std::string& passphrase = {});
    static Key fromPublicDer(const Bytes& spkiDer);

    std::string privatePem(const std::string& passphrase = {}) const;
    Bytes publicDer() const;
    // base32(sha256(SubjectPublicKeyInfo DER)).
    std::string fingerprint() const;
    bool hasPrivate() const;
    bool isA(const char* algorithmName) const;
    bool hasKem() const;
    const Key& kem() const;

    EVP_PKEY* raw() const;

private:
    friend class Identity;

    explicit Key(KeyPtr key, bool hasPrivate);
    Key(KeyPtr classical, KeyPtr kem, bool hasPrivate);

    KeyPtr key_;
    std::shared_ptr<Key> kem_;
    bool hasPrivate_;
};

Bytes sign(const Key& key, const Bytes& data);
bool verify(const Key& key, const Bytes& data, const Bytes& signature);

Bytes sha256(const Bytes& data);

inline constexpr std::size_t kAeadKeyBytes = 32;
inline constexpr std::size_t kAeadNonceBytes = 12;
inline constexpr std::size_t kAeadTagBytes = 16;
Bytes aeadSeal(const Bytes& key, const Bytes& nonce, const Bytes& plaintext);
std::optional<Bytes> aeadOpen(const Bytes& key, const Bytes& nonce, const Bytes& sealed);

Bytes sha256File(const std::filesystem::path& path);

class Identity {
public:
    static Identity generate();
    // Reads two PEM blocks: the classical key first, the ML-DSA key second.
    static Identity fromPrivatePem(const std::string& pem, const std::string& passphrase = {});
    Identity(Key classical, Key pq);

    const Key& classical() const;
    const Key& pq() const;
    std::string privatePem(const std::string& passphrase = {}) const;
    std::string fingerprint() const;

private:
    Key classical_;
    Key pq_;
};

std::string hybridFingerprint(const Bytes& classicalPublicDer, const Bytes& pqPublicDer);

}  // namespace bazarish
