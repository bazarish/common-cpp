// Bazarish project (c) 2026
#include "bazarish/Crypto.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdexcept>

namespace {

using bazarish::Bytes;

bazarish::KeyPtr generateEcP256()
{
    EVP_PKEY* const key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    if (key == nullptr) {
        throw std::runtime_error("EC P-256 keygen failed");
    }
    return bazarish::KeyPtr(key);
}

struct BioDeleter {
    void operator()(BIO* bio) const
    {
        BIO_free(bio);
    }
};
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

BioPtr makeMemoryBio()
{
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new failed");
    }
    return bio;
}

Bytes bioToBytes(BIO* const bio)
{
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    if (size < 0 || data == nullptr) {
        throw std::runtime_error("BIO_get_mem_data failed");
    }
    return Bytes(data, data + size);
}

}  // namespace

namespace bazarish {

void EvpPkeyDeleter::operator()(EVP_PKEY* const key) const
{
    EVP_PKEY_free(key);
}

Key::Key(KeyPtr key, const bool hasPrivate)
    : key_(std::move(key))
    , hasPrivate_(hasPrivate)
{
}

Key Key::generateSigning()
{
    return Key(generateEcP256(), true);
}

Key Key::generateSigningPq()
{
    EVP_PKEY* const key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-65");
    if (key == nullptr) {
        throw std::runtime_error("ML-DSA-65 keygen failed");
    }
    return Key(KeyPtr(key), true);
}

Key Key::generateSealing()
{
    return Key(generateEcP256(), true);
}

Key Key::fromPrivatePem(const std::string& pem, const std::string& passphrase)
{
    const BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new_mem_buf failed");
    }
    // When the passphrase is empty OpenSSL receives a null userdata and reads
    // an unencrypted PEM; otherwise the default callback uses it as the
    // password for the encrypted block.
    void* const password = passphrase.empty() ? nullptr
                                               : const_cast<char*>(passphrase.c_str());
    EVP_PKEY* const key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, password);
    if (key == nullptr) {
        throw std::runtime_error("PEM_read_bio_PrivateKey failed");
    }
    return Key(KeyPtr(key), true);
}

Key Key::fromPublicDer(const Bytes& spkiDer)
{
    const unsigned char* cursor = spkiDer.data();
    EVP_PKEY* const key = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(spkiDer.size()));
    if (key == nullptr) {
        throw std::runtime_error("d2i_PUBKEY failed");
    }
    return Key(KeyPtr(key), false);
}

std::string Key::privatePem(const std::string& passphrase) const
{
    if (!hasPrivate_) {
        throw std::logic_error("key has no private part");
    }
    const BioPtr bio = makeMemoryBio();
    // A non-empty passphrase selects AES-256-CBC encryption of the PEM block;
    // an empty one keeps the unencrypted form.
    const EVP_CIPHER* const cipher = passphrase.empty() ? nullptr : EVP_aes_256_cbc();
    unsigned char* const pass = passphrase.empty()
        ? nullptr
        : reinterpret_cast<unsigned char*>(const_cast<char*>(passphrase.data()));
    if (PEM_write_bio_PrivateKey(bio.get(), key_.get(), cipher, pass,
            static_cast<int>(passphrase.size()), nullptr, nullptr)
        != 1) {
        throw std::runtime_error("PEM_write_bio_PrivateKey failed");
    }
    const Bytes data = bioToBytes(bio.get());
    return std::string(data.begin(), data.end());
}

Bytes Key::publicDer() const
{
    const BioPtr bio = makeMemoryBio();
    if (i2d_PUBKEY_bio(bio.get(), key_.get()) != 1) {
        throw std::runtime_error("i2d_PUBKEY_bio failed");
    }
    return bioToBytes(bio.get());
}

std::string Key::fingerprint() const
{
    return toBase32(sha256(publicDer()));
}

bool Key::hasPrivate() const
{
    return hasPrivate_;
}

bool Key::isA(const char* const algorithmName) const
{
    return EVP_PKEY_is_a(key_.get(), algorithmName) == 1;
}

EVP_PKEY* Key::raw() const
{
    return key_.get();
}

Bytes sign(const Key& key, const Bytes& data)
{
    if (!key.hasPrivate()) {
        throw std::logic_error("signing requires a private key");
    }
    EVP_MD_CTX* const ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    // EC signs a SHA-256 digest; ML-DSA signs the message directly.
    const EVP_MD* const digest = key.isA("EC") ? EVP_sha256() : nullptr;
    Bytes signature;
    bool ok = EVP_DigestSignInit(ctx, nullptr, digest, nullptr, key.raw()) == 1;
    if (ok) {
        std::size_t size = 0;
        ok = EVP_DigestSign(ctx, nullptr, &size, data.data(), data.size()) == 1;
        if (ok) {
            signature.resize(size);
            ok = EVP_DigestSign(ctx, signature.data(), &size, data.data(), data.size()) == 1;
            signature.resize(size);
        }
    }
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        throw std::runtime_error("EVP_DigestSign failed");
    }
    return signature;
}

bool verify(const Key& key, const Bytes& data, const Bytes& signature)
{
    EVP_MD_CTX* const ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    const EVP_MD* const digest = key.isA("EC") ? EVP_sha256() : nullptr;
    bool ok = EVP_DigestVerifyInit(ctx, nullptr, digest, nullptr, key.raw()) == 1;
    if (ok) {
        ok = EVP_DigestVerify(
                 ctx, signature.data(), signature.size(), data.data(), data.size())
            == 1;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

Bytes sha256(const Bytes& data)
{
    Bytes digest(kFingerprintBytes);
    unsigned int size = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &size, EVP_sha256(), nullptr) != 1
        || size != kFingerprintBytes) {
        throw std::runtime_error("EVP_Digest failed");
    }
    return digest;
}

Identity::Identity(Key classical, Key pq)
    : classical_(std::move(classical))
    , pq_(std::move(pq))
{
    if (!classical_.isA("EC")) {
        throw std::invalid_argument("classical identity key must be EC");
    }
    if (!pq_.isA("ML-DSA-65")) {
        throw std::invalid_argument("post-quantum identity key must be ML-DSA-65");
    }
}

Identity Identity::generate()
{
    return Identity(Key::generateSigning(), Key::generateSigningPq());
}

Identity Identity::fromPrivatePem(const std::string& pem, const std::string& passphrase)
{
    const BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new_mem_buf failed");
    }
    void* const password = passphrase.empty() ? nullptr
                                               : const_cast<char*>(passphrase.c_str());
    EVP_PKEY* const first = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, password);
    if (first == nullptr) {
        throw std::runtime_error("identity PEM: first key unreadable");
    }
    Key classical(KeyPtr(first), true);
    EVP_PKEY* const second = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, password);
    if (second == nullptr) {
        throw std::runtime_error("identity PEM: second key unreadable");
    }
    Key pq(KeyPtr(second), true);
    return Identity(std::move(classical), std::move(pq));
}

const Key& Identity::classical() const
{
    return classical_;
}

const Key& Identity::pq() const
{
    return pq_;
}

std::string Identity::privatePem(const std::string& passphrase) const
{
    return classical_.privatePem(passphrase) + pq_.privatePem(passphrase);
}

std::string Identity::fingerprint() const
{
    return hybridFingerprint(classical_.publicDer(), pq_.publicDer());
}

std::string hybridFingerprint(const Bytes& classicalPublicDer, const Bytes& pqPublicDer)
{
    Bytes joined = classicalPublicDer;
    joined.insert(joined.end(), pqPublicDer.begin(), pqPublicDer.end());
    return toBase32(sha256(joined));
}

}  // namespace bazarish
