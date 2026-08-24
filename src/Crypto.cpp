// Bazarish project (c) 2026
#include "bazarish/Crypto.hpp"

#include <openssl/bio.h>
#include <nlohmann/json.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>

namespace {

using bazarish::Bytes;

// The post-quantum half of every sealing key (FIPS 203). ML-KEM-768 is the
// category-3 parameter set, matching ML-DSA-65 on the signing side.
constexpr const char* kKemAlgorithm = "ML-KEM-768";

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

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const
    {
        EVP_CIPHER_CTX_free(ctx);
    }
};
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

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

Key::Key(KeyPtr classical, KeyPtr kem, const bool hasPrivate)
    : key_(std::move(classical))
    , kem_(std::make_shared<Key>(Key(std::move(kem), hasPrivate)))
    , hasPrivate_(hasPrivate)
{
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
    // Hybrid by construction: there is no way to make a sealing key that is
    // only classical, so nothing downstream can accidentally seal with one.
    EVP_PKEY* const kem = EVP_PKEY_Q_keygen(nullptr, nullptr, kKemAlgorithm);
    if (kem == nullptr) {
        throw std::runtime_error("ML-KEM-768 keygen failed");
    }
    return Key(generateEcP256(), KeyPtr(kem), true);
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
    // A sealing key is written as two blocks, classical first: read the second
    // when it is there, so a key round-trips through PEM with both halves.
    EVP_PKEY* const second = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, password);
    if (second == nullptr) {
        ERR_clear_error();  // one block: not an error, just a single key
        return Key(KeyPtr(key), true);
    }
    return Key(KeyPtr(key), KeyPtr(second), true);
}

namespace {

// A hybrid sealing key travels as this pair; a single key travels as its bare
// SPKI. The tag is what tells them apart without guessing.
constexpr const char* kSealingPairTag = "bzsk1";

}  // namespace

Key Key::fromPublicDer(const Bytes& spkiDer)
{
    // The pair form is CBOR; a bare SPKI is DER. Try the pair first - it is
    // self-identifying, so a bare SPKI cannot be mistaken for one.
    if (!spkiDer.empty()) {
        // Asked not to throw: "this is not CBOR" is the ordinary case here (a
        // bare SPKI), not an error to report.
        const nlohmann::json pair
            = nlohmann::json::from_cbor(spkiDer, true, false, nlohmann::json::cbor_tag_handler_t::error);
        {
            if (pair.is_object() && pair.value("t", std::string()) == kSealingPairTag) {
                const nlohmann::json::binary_t& classical = pair.at("c").get_binary();
                const nlohmann::json::binary_t& kem = pair.at("q").get_binary();
                const unsigned char* classicalCursor = classical.data();
                EVP_PKEY* const classicalKey = d2i_PUBKEY(
                    nullptr, &classicalCursor, static_cast<long>(classical.size()));
                const unsigned char* kemCursor = kem.data();
                EVP_PKEY* const kemKey
                    = d2i_PUBKEY(nullptr, &kemCursor, static_cast<long>(kem.size()));
                if (classicalKey == nullptr || kemKey == nullptr) {
                    EVP_PKEY_free(classicalKey);
                    EVP_PKEY_free(kemKey);
                    throw std::runtime_error("sealing key pair does not parse");
                }
                return Key(KeyPtr(classicalKey), KeyPtr(kemKey), false);
            }
        }
    }
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
    // A sealing key is two keys, so it is two PEM blocks: the classical one
    // first, the ML-KEM one second (the same order Identity uses).
    return std::string(data.begin(), data.end()) + (kem_ ? kem_->privatePem(passphrase) : "");
}

Bytes Key::publicDer() const
{
    const BioPtr bio = makeMemoryBio();
    if (i2d_PUBKEY_bio(bio.get(), key_.get()) != 1) {
        throw std::runtime_error("i2d_PUBKEY_bio failed");
    }
    const Bytes classical = bioToBytes(bio.get());
    if (!kem_) {
        return classical;
    }
    const nlohmann::json pair = {
        {"t", kSealingPairTag},
        {"c", nlohmann::json::binary(classical)},
        {"q", nlohmann::json::binary(kem_->publicDer())},
    };
    return nlohmann::json::to_cbor(pair);
}

bool Key::hasKem() const
{
    return static_cast<bool>(kem_);
}

const Key& Key::kem() const
{
    if (!kem_) {
        throw std::logic_error("key carries no ML-KEM half");
    }
    return *kem_;
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
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    // EC signs a SHA-256 digest; ML-DSA signs the message directly.
    const EVP_MD* const digest = key.isA("EC") ? EVP_sha256() : nullptr;
    Bytes signature;
    bool ok = EVP_DigestSignInit(ctx.get(), nullptr, digest, nullptr, key.raw()) == 1;
    if (ok) {
        std::size_t size = 0;
        ok = EVP_DigestSign(ctx.get(), nullptr, &size, data.data(), data.size()) == 1;
        if (ok) {
            signature.resize(size);
            ok = EVP_DigestSign(ctx.get(), signature.data(), &size, data.data(), data.size()) == 1;
            signature.resize(size);
        }
    }
    if (!ok) {
        throw std::runtime_error("EVP_DigestSign failed");
    }
    return signature;
}

bool verify(const Key& key, const Bytes& data, const Bytes& signature)
{
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    const EVP_MD* const digest = key.isA("EC") ? EVP_sha256() : nullptr;
    bool ok = EVP_DigestVerifyInit(ctx.get(), nullptr, digest, nullptr, key.raw()) == 1;
    if (ok) {
        ok = EVP_DigestVerify(
                 ctx.get(), signature.data(), signature.size(), data.data(), data.size())
            == 1;
    }
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

Bytes aeadSeal(const Bytes& key, const Bytes& nonce, const Bytes& plaintext)
{
    if (key.size() != kAeadKeyBytes || nonce.size() != kAeadNonceBytes) {
        throw std::invalid_argument("aeadSeal: wrong key or nonce size");
    }
    const CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (ctx == nullptr
        || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1
        || EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
               static_cast<int>(kAeadNonceBytes), nullptr)
            != 1
        || EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw std::runtime_error("aeadSeal: init failed");
    }
    Bytes out(plaintext.size() + kAeadTagBytes);
    int len = 0;
    if (EVP_EncryptUpdate(ctx.get(), out.data(), &len, plaintext.data(),
            static_cast<int>(plaintext.size()))
        != 1) {
        throw std::runtime_error("aeadSeal: encrypt failed");
    }
    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + len, &finalLen) != 1) {
        throw std::runtime_error("aeadSeal: finalize failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kAeadTagBytes),
            out.data() + plaintext.size())
        != 1) {
        throw std::runtime_error("aeadSeal: get tag failed");
    }
    return out;
}

std::optional<Bytes> aeadOpen(const Bytes& key, const Bytes& nonce, const Bytes& sealed)
{
    if (key.size() != kAeadKeyBytes || nonce.size() != kAeadNonceBytes) {
        throw std::invalid_argument("aeadOpen: wrong key or nonce size");
    }
    if (sealed.size() < kAeadTagBytes) {
        return std::nullopt;  // too short to carry a tag: malformed, not authentic
    }
    const std::size_t cipherLen = sealed.size() - kAeadTagBytes;
    const CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (ctx == nullptr
        || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1
        || EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
               static_cast<int>(kAeadNonceBytes), nullptr)
            != 1
        || EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw std::runtime_error("aeadOpen: init failed");
    }
    Bytes out(cipherLen);
    int len = 0;
    if (EVP_DecryptUpdate(ctx.get(), out.data(), &len, sealed.data(),
            static_cast<int>(cipherLen))
        != 1) {
        throw std::runtime_error("aeadOpen: decrypt failed");
    }
    // The trailing 16 bytes are the GCM tag; a mismatch fails DecryptFinal.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kAeadTagBytes),
            const_cast<unsigned char*>(sealed.data() + cipherLen))
        != 1) {
        throw std::runtime_error("aeadOpen: set tag failed");
    }
    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + len, &finalLen) != 1) {
        return std::nullopt;  // authentication failed
    }
    return out;
}

Bytes sha256File(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open file for hashing: " + path.string());
    }
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (ctx == nullptr || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    std::array<char, 64 * 1024> buffer;
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = input.gcount();
        if (got > 0
            && EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<std::size_t>(got)) != 1) {
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
    }
    if (input.bad()) {
        throw std::runtime_error("read error while hashing: " + path.string());
    }
    Bytes digest(kFingerprintBytes);
    unsigned int size = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &size) != 1 || size != kFingerprintBytes) {
        throw std::runtime_error("EVP_DigestFinal_ex failed");
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
