// Bazarish project (c) 2026
#include "bazarish/Cms.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/x509.h>

#include <filesystem>
#include <cstring>
#include <stdexcept>

namespace {

using bazarish::Bytes;
using bazarish::Key;

// Carrier certificates exist only to transport a public key through CMS
// structures; validity is set wide so clock skew can never interfere.
// Counted in days: a century of seconds does not fit the long that the
// seconds-taking call has for it where long is 32 bits.
constexpr int kCarrierCertValidityDays = 365 * 100;

struct BioDeleter {
    void operator()(BIO* bio) const
    {
        BIO_free(bio);
    }
};
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

struct X509Deleter {
    void operator()(X509* cert) const
    {
        X509_free(cert);
    }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

struct CmsDeleter {
    void operator()(CMS_ContentInfo* cms) const
    {
        CMS_ContentInfo_free(cms);
    }
};
using CmsPtr = std::unique_ptr<CMS_ContentInfo, CmsDeleter>;

struct BnDeleter {
    void operator()(BIGNUM* bn) const
    {
        BN_free(bn);
    }
};
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;

// Frees the stack container only (sk_X509_free), not its elements - matching
// both the get0 borrow (CMS_get0_signers) and the push-of-an-owned-cert case.
struct StackOfX509Deleter {
    void operator()(STACK_OF(X509)* stack) const
    {
        sk_X509_free(stack);
    }
};
using StackOfX509Ptr = std::unique_ptr<STACK_OF(X509), StackOfX509Deleter>;

BioPtr makeMemoryBio()
{
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new failed");
    }
    return bio;
}

BioPtr makeInputBio(const Bytes& data)
{
    BioPtr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new_mem_buf failed");
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

// Builds a carrier X.509 certificate for subjectKey. The certificate is
// signed by signerKey, which must be capable of signing; for self-signed
// identity carriers signerKey == subjectKey.
X509Ptr makeCarrierCert(const Key& subjectKey, const Key& signerKey)
{
    X509Ptr cert(X509_new());
    if (cert == nullptr) {
        throw std::runtime_error("X509_new failed");
    }
    bool ok = X509_set_version(cert.get(), X509_VERSION_3) == 1;

    if (ok) {
        const Bytes serial = bazarish::randomBytes(8);
        const BnPtr serialBn(BN_bin2bn(serial.data(), static_cast<int>(serial.size()), nullptr));
        ok = serialBn != nullptr
            && BN_to_ASN1_INTEGER(serialBn.get(), X509_get_serialNumber(cert.get())) != nullptr;
    }

    if (ok) {
        const std::string commonName = subjectKey.fingerprint();
        X509_NAME* const name = X509_get_subject_name(cert.get());
        ok = X509_NAME_add_entry_by_txt(
                 name, "CN", MBSTRING_ASC,
                 reinterpret_cast<const unsigned char*>(commonName.c_str()), -1, -1, 0)
                == 1
            && X509_set_issuer_name(cert.get(), name) == 1;
    }

    ok = ok && X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600) != nullptr
        && X509_time_adj_ex(X509_getm_notAfter(cert.get()), kCarrierCertValidityDays, 0,
               nullptr)
            != nullptr
        && X509_set_pubkey(cert.get(), subjectKey.raw()) == 1;

    ok = ok && X509_sign(cert.get(), signerKey.raw(), EVP_sha256()) > 0;

    if (!ok) {
        throw std::runtime_error("carrier certificate creation failed");
    }
    return cert;
}

BioPtr makeReadFileBio(const std::filesystem::path& path)
{
    BioPtr bio(BIO_new_file(path.string().c_str(), "rb"));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new_file (read) failed: " + path.string());
    }
    return bio;
}

BioPtr makeWriteFileBio(const std::filesystem::path& path)
{
    BioPtr bio(BIO_new_file(path.string().c_str(), "wb"));
    if (bio == nullptr) {
        throw std::runtime_error("BIO_new_file (write) failed: " + path.string());
    }
    return bio;
}

// Password-based CMS decrypt from input to output BIO; shared by the in-memory
// and the streamed-to-file variants. The recipient key arguments are null: the
// password set here is the key source. A wrong password surfaces as a decrypt
// failure. CMS_decrypt streams the recovered content to the output BIO, so with
// a file output BIO the cleartext is never buffered whole in memory.
void unsealWithPasswordBio(BIO* const input, BIO* const output, const std::string& password)
{
    const CmsPtr cms(d2i_CMS_bio(input, nullptr));
    if (cms == nullptr) {
        throw std::runtime_error("d2i_CMS_bio failed");
    }
    if (CMS_decrypt_set1_password(cms.get(),
            reinterpret_cast<unsigned char*>(const_cast<char*>(password.data())),
            static_cast<int>(password.size()))
        != 1) {
        throw std::runtime_error("CMS_decrypt_set1_password failed");
    }
    if (CMS_decrypt(cms.get(), nullptr, nullptr, nullptr, output, CMS_BINARY) != 1) {
        throw std::runtime_error("CMS_decrypt failed (wrong password?)");
    }
}

}  // namespace

namespace bazarish::cms {

Bytes signJson(const nlohmann::json& body, const Key& signingKey)
{
    if (!signingKey.hasPrivate()) {
        throw std::logic_error("CMS signing requires a private key");
    }
    const std::string serialized = body.dump();
    const Bytes payload(serialized.begin(), serialized.end());

    const X509Ptr cert = makeCarrierCert(signingKey, signingKey);
    const BioPtr input = makeInputBio(payload);

    const CmsPtr cms(CMS_sign(cert.get(), signingKey.raw(), nullptr, input.get(), CMS_BINARY));
    if (cms == nullptr) {
        throw std::runtime_error("CMS_sign failed");
    }

    const BioPtr output = makeMemoryBio();
    if (i2d_CMS_bio(output.get(), cms.get()) != 1) {
        throw std::runtime_error("i2d_CMS_bio failed");
    }
    return bioToBytes(output.get());
}

VerifiedJson verifyJson(const Bytes& der)
{
    const BioPtr input = makeInputBio(der);
    const CmsPtr cms(d2i_CMS_bio(input.get(), nullptr));
    if (cms == nullptr) {
        throw std::runtime_error("d2i_CMS_bio failed");
    }

    // The embedded certificate is a key carrier, not a chain: verify the
    // signature only and let the caller judge the signer fingerprint.
    const BioPtr output = makeMemoryBio();
    if (CMS_verify(cms.get(), nullptr, nullptr, nullptr, output.get(),
            CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY)
        != 1) {
        throw std::runtime_error("CMS_verify failed");
    }

    const StackOfX509Ptr signers(CMS_get0_signers(cms.get()));
    if (signers == nullptr || sk_X509_num(signers.get()) != 1) {
        throw std::runtime_error("CMS signer extraction failed");
    }
    EVP_PKEY* const signerPubkey = X509_get0_pubkey(sk_X509_value(signers.get(), 0));
    if (signerPubkey == nullptr) {
        throw std::runtime_error("CMS signer has no public key");
    }

    // Re-encode the signer key through the canonical SPKI DER form.
    const BioPtr keyBio = makeMemoryBio();
    if (i2d_PUBKEY_bio(keyBio.get(), signerPubkey) != 1) {
        throw std::runtime_error("i2d_PUBKEY_bio failed");
    }
    Bytes signerDer = bioToBytes(keyBio.get());
    const Key signerKey = Key::fromPublicDer(signerDer);

    const Bytes payload = bioToBytes(output.get());
    return VerifiedJson{
        nlohmann::json::parse(payload.begin(), payload.end()),
        signerKey.fingerprint(),
        std::move(signerDer),
    };
}

Bytes signJsonHybrid(const nlohmann::json& body, const Identity& identity)
{
    const std::string serialized = body.dump();
    const Bytes bodyBytes(serialized.begin(), serialized.end());
    const Bytes pqSignature = sign(identity.pq(), bodyBytes);

    const nlohmann::json wrapper = {
        {"body", toBase64(bodyBytes)},
        {"pq",
            {
                {"alg", "ML-DSA-65"},
                {"pub", toBase64(identity.pq().publicDer())},
                {"sig", toBase64(pqSignature)},
            }},
    };
    return signJson(wrapper, identity.classical());
}

VerifiedHybridJson verifyJsonHybrid(const Bytes& der)
{
    const VerifiedJson outer = verifyJson(der);

    const Key classicalKey = Key::fromPublicDer(outer.signerPublicDer);
    if (!classicalKey.isA("EC")) {
        throw std::runtime_error("hybrid statement: classical signer is not EC");
    }

    const nlohmann::json& pq = outer.body.at("pq");
    if (pq.at("alg").get<std::string>() != "ML-DSA-65") {
        throw std::runtime_error("hybrid statement: unexpected pq algorithm");
    }
    const Bytes bodyBytes = fromBase64(outer.body.at("body").get<std::string>());
    const Bytes pqPublicDer = fromBase64(pq.at("pub").get<std::string>());
    const Bytes pqSignature = fromBase64(pq.at("sig").get<std::string>());

    const Key pqKey = Key::fromPublicDer(pqPublicDer);
    if (!pqKey.isA("ML-DSA-65")) {
        throw std::runtime_error("hybrid statement: pq key is not ML-DSA-65");
    }
    if (!verify(pqKey, bodyBytes, pqSignature)) {
        throw std::runtime_error("hybrid statement: pq signature verification failed");
    }

    return VerifiedHybridJson{
        nlohmann::json::parse(bodyBytes.begin(), bodyBytes.end()),
        hybridFingerprint(outer.signerPublicDer, pqPublicDer),
    };
}

namespace {

// The shape of a hybrid sealed blob, inside the CMS EnvelopedData. It is
// versioned so the post-quantum half can move into CMS itself the day OpenSSL
// grows KEMRecipientInfo (RFC 9629) without changing the container or breaking
// anything already written:
//
//   v=1  the KEM ciphertext travels here and the payload is encrypted under the
//        secret it carries (today: OpenSSL CMS has no KEM recipient - checked
//        against 3.5, whose cms.h knows only TRANS/AGREE/KEK/PASS/OTHER).
//   v=2  reserved: the KEM recipient sits in the CMS, and this wrapper carries
//        the payload alone. Readers dispatch on `v`, so v=1 keeps opening.
constexpr int kHybridSealVersion = 1;
constexpr const char* kSealInfo = "bazarish-hybrid-seal-v1";
// AES-256-GCM as used everywhere else in the project.
constexpr int kSealKeyBytes = 32;
constexpr int kSealNonceBytes = 12;
constexpr int kSealTagBytes = 16;

// HKDF-SHA256 over the KEM shared secret. The KEM ciphertext is the salt, so
// the key is bound to the exact encapsulation it came from.
Bytes sealKeyFrom(const Bytes& sharedSecret, const Bytes& kemCiphertext)
{
    EVP_KDF* const kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf == nullptr) {
        throw std::runtime_error("HKDF unavailable");
    }
    EVP_KDF_CTX* const ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_KDF_CTX_new failed");
    }
    Bytes key(kSealKeyBytes);
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(sharedSecret.data()),
            sharedSecret.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(kemCiphertext.data()),
            kemCiphertext.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, const_cast<char*>(kSealInfo), std::strlen(kSealInfo)),
        OSSL_PARAM_construct_end(),
    };
    const int ok = EVP_KDF_derive(ctx, key.data(), key.size(), params);
    EVP_KDF_CTX_free(ctx);
    if (ok != 1) {
        throw std::runtime_error("HKDF derive failed");
    }
    return key;
}

Bytes aesGcm(const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& input,
    const bool encrypting)
{
    EVP_CIPHER_CTX* const ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }
    const struct Guard {
        EVP_CIPHER_CTX* ctx;
        ~Guard() { EVP_CIPHER_CTX_free(ctx); }
    } guard{ctx};

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr, encrypting ? 1 : 0)
            != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, kSealNonceBytes, nullptr) != 1
        || EVP_CipherInit_ex(
               ctx, nullptr, nullptr, key.data(), nonce.data(), encrypting ? 1 : 0)
            != 1) {
        throw std::runtime_error("AES-GCM init failed");
    }
    int length = 0;
    if (!aad.empty()
        && EVP_CipherUpdate(ctx, nullptr, &length, aad.data(), static_cast<int>(aad.size()))
            != 1) {
        throw std::runtime_error("AES-GCM aad failed");
    }
    if (encrypting) {
        Bytes out(input.size() + kSealTagBytes);
        if (EVP_CipherUpdate(ctx, out.data(), &length, input.data(),
                static_cast<int>(input.size()))
            != 1) {
            throw std::runtime_error("AES-GCM encrypt failed");
        }
        int finalLength = 0;
        if (EVP_CipherFinal_ex(ctx, out.data() + length, &finalLength) != 1) {
            throw std::runtime_error("AES-GCM finalise failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, kSealTagBytes,
                out.data() + input.size())
            != 1) {
            throw std::runtime_error("AES-GCM tag failed");
        }
        return out;
    }
    if (input.size() < static_cast<std::size_t>(kSealTagBytes)) {
        throw std::runtime_error("sealed payload is too short to carry a tag");
    }
    const std::size_t bodyLength = input.size() - kSealTagBytes;
    Bytes out(bodyLength);
    if (EVP_CipherUpdate(ctx, out.data(), &length, input.data(), static_cast<int>(bodyLength))
        != 1) {
        throw std::runtime_error("AES-GCM decrypt failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, kSealTagBytes,
            const_cast<unsigned char*>(input.data() + bodyLength))
        != 1) {
        throw std::runtime_error("AES-GCM set tag failed");
    }
    int finalLength = 0;
    if (EVP_CipherFinal_ex(ctx, out.data() + length, &finalLength) != 1) {
        throw std::runtime_error("sealed payload does not authenticate");
    }
    return out;
}

}  // namespace

Bytes seal(const Bytes& plaintext, const Key& recipientPublicKey)
{
    if (!recipientPublicKey.hasKem()) {
        // Sealing to a classical-only key would be confidentiality that a
        // quantum adversary can harvest today and open later. There is no such
        // sealing key in this protocol, so this is a programming error.
        throw std::logic_error("sealing requires a hybrid (ML-KEM) recipient key");
    }
    // Post-quantum half: encapsulate to the recipient's ML-KEM key and encrypt
    // the payload under the secret it yields. The classical CMS layer below
    // then encrypts this whole wrapper, so opening it needs both private keys.
    EVP_PKEY_CTX* const kemCtx = EVP_PKEY_CTX_new(recipientPublicKey.kem().raw(), nullptr);
    if (kemCtx == nullptr || EVP_PKEY_encapsulate_init(kemCtx, nullptr) != 1) {
        EVP_PKEY_CTX_free(kemCtx);
        throw std::runtime_error("ML-KEM encapsulate init failed");
    }
    std::size_t ciphertextLength = 0;
    std::size_t secretLength = 0;
    if (EVP_PKEY_encapsulate(kemCtx, nullptr, &ciphertextLength, nullptr, &secretLength) != 1) {
        EVP_PKEY_CTX_free(kemCtx);
        throw std::runtime_error("ML-KEM encapsulate sizing failed");
    }
    Bytes kemCiphertext(ciphertextLength);
    Bytes sharedSecret(secretLength);
    const int encapsulated = EVP_PKEY_encapsulate(
        kemCtx, kemCiphertext.data(), &ciphertextLength, sharedSecret.data(), &secretLength);
    EVP_PKEY_CTX_free(kemCtx);
    if (encapsulated != 1) {
        throw std::runtime_error("ML-KEM encapsulate failed");
    }
    kemCiphertext.resize(ciphertextLength);
    sharedSecret.resize(secretLength);

    const Bytes nonce = randomBytes(kSealNonceBytes);
    const Bytes inner = aesGcm(sealKeyFrom(sharedSecret, kemCiphertext), nonce, kemCiphertext,
        plaintext, true);
    const nlohmann::json wrapper = {
        {"v", kHybridSealVersion},
        {"kem", nlohmann::json::binary(kemCiphertext)},
        {"n", nlohmann::json::binary(nonce)},
        {"ct", nlohmann::json::binary(inner)},
    };
    const Bytes wrapped = nlohmann::json::to_cbor(wrapper);

    // The carrier certificate is signed by a throwaway signing key;
    // only the embedded recipient public key matters.
    const Key throwaway = Key::generateSigning();
    const X509Ptr carrier = makeCarrierCert(recipientPublicKey, throwaway);

    const StackOfX509Ptr recipients(sk_X509_new_null());
    if (recipients == nullptr || sk_X509_push(recipients.get(), carrier.get()) <= 0) {
        throw std::runtime_error("recipient stack creation failed");
    }

    const BioPtr input = makeInputBio(wrapped);
    const CmsPtr cms(
        CMS_encrypt(recipients.get(), input.get(), EVP_aes_256_gcm(), CMS_BINARY));
    if (cms == nullptr) {
        throw std::runtime_error("CMS_encrypt failed");
    }

    const BioPtr output = makeMemoryBio();
    if (i2d_CMS_bio(output.get(), cms.get()) != 1) {
        throw std::runtime_error("i2d_CMS_bio failed");
    }
    return bioToBytes(output.get());
}

Bytes unseal(const Bytes& der, const Key& recipientPrivateKey)
{
    if (!recipientPrivateKey.hasPrivate()) {
        throw std::logic_error("unsealing requires a private key");
    }
    const BioPtr input = makeInputBio(der);
    const CmsPtr cms(d2i_CMS_bio(input.get(), nullptr));
    if (cms == nullptr) {
        throw std::runtime_error("d2i_CMS_bio failed");
    }

    const BioPtr output = makeMemoryBio();
    if (CMS_decrypt(cms.get(), recipientPrivateKey.raw(), nullptr, nullptr, output.get(),
            CMS_BINARY)
        != 1) {
        throw std::runtime_error("CMS_decrypt failed");
    }
    const Bytes wrapped = bioToBytes(output.get());
    if (!recipientPrivateKey.hasKem()) {
        throw std::logic_error("unsealing requires a hybrid (ML-KEM) key");
    }

    const nlohmann::json wrapper = nlohmann::json::from_cbor(wrapped);
    const int version = wrapper.at("v").get<int>();
    if (version != kHybridSealVersion) {
        // A blob written by a build that carries the KEM recipient in the CMS
        // itself: this one cannot open it, and must not pretend otherwise.
        throw std::runtime_error(
            "sealed blob is version " + std::to_string(version) + ", this build reads version "
                + std::to_string(kHybridSealVersion));
    }
    const nlohmann::json::binary_t& kemCiphertext = wrapper.at("kem").get_binary();
    const nlohmann::json::binary_t& nonce = wrapper.at("n").get_binary();
    const nlohmann::json::binary_t& inner = wrapper.at("ct").get_binary();

    EVP_PKEY_CTX* const kemCtx = EVP_PKEY_CTX_new(recipientPrivateKey.kem().raw(), nullptr);
    if (kemCtx == nullptr || EVP_PKEY_decapsulate_init(kemCtx, nullptr) != 1) {
        EVP_PKEY_CTX_free(kemCtx);
        throw std::runtime_error("ML-KEM decapsulate init failed");
    }
    std::size_t secretLength = 0;
    if (EVP_PKEY_decapsulate(kemCtx, nullptr, &secretLength, kemCiphertext.data(),
            kemCiphertext.size())
        != 1) {
        EVP_PKEY_CTX_free(kemCtx);
        throw std::runtime_error("ML-KEM decapsulate sizing failed");
    }
    Bytes sharedSecret(secretLength);
    const int decapsulated = EVP_PKEY_decapsulate(kemCtx, sharedSecret.data(), &secretLength,
        kemCiphertext.data(), kemCiphertext.size());
    EVP_PKEY_CTX_free(kemCtx);
    if (decapsulated != 1) {
        throw std::runtime_error("ML-KEM decapsulate failed");
    }
    sharedSecret.resize(secretLength);

    return aesGcm(sealKeyFrom(sharedSecret, Bytes(kemCiphertext.begin(), kemCiphertext.end())),
        Bytes(nonce.begin(), nonce.end()), Bytes(kemCiphertext.begin(), kemCiphertext.end()),
        Bytes(inner.begin(), inner.end()), false);
}

Bytes sealWithPassword(const Bytes& plaintext, const std::string& password)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr input = makeInputBio(plaintext);
    // CMS_PARTIAL leaves the structure open so a password recipient can be
    // added before finalizing; the content is AES-256-CBC.
    const CmsPtr cms(CMS_encrypt(nullptr, input.get(), EVP_aes_256_cbc(),
        CMS_BINARY | CMS_PARTIAL));
    if (cms == nullptr) {
        throw std::runtime_error("CMS_encrypt failed");
    }
    // CMS_add0_recipient_password takes ownership of the password buffer and
    // frees it with the structure, so it must be an OpenSSL allocation, not
    // our std::string's storage. Default PBKDF2 iteration count and PWRI key
    // wrap; the password key encryption key is AES-256.
    unsigned char* const passCopy
        = static_cast<unsigned char*>(OPENSSL_memdup(password.data(), password.size()));
    if (passCopy == nullptr) {
        throw std::runtime_error("OPENSSL_memdup failed");
    }
    if (CMS_add0_recipient_password(cms.get(), -1, NID_undef, NID_undef, passCopy,
            static_cast<int>(password.size()), nullptr)
        == nullptr) {
        OPENSSL_free(passCopy);
        throw std::runtime_error("CMS_add0_recipient_password failed");
    }
    if (CMS_final(cms.get(), input.get(), nullptr, CMS_BINARY) != 1) {
        throw std::runtime_error("CMS_final failed");
    }

    const BioPtr output = makeMemoryBio();
    if (i2d_CMS_bio(output.get(), cms.get()) != 1) {
        throw std::runtime_error("i2d_CMS_bio failed");
    }
    return bioToBytes(output.get());
}

void sealWithPasswordToFile(const std::filesystem::path& inPath,
    const std::filesystem::path& outPath, const std::string& password)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr input = makeReadFileBio(inPath);
    const BioPtr output = makeWriteFileBio(outPath);
    // CMS_PARTIAL leaves the structure open for the password recipient; CMS_STREAM
    // makes the content be pulled from `input` lazily during serialization, so the
    // plaintext is never held whole in memory. AES-256-CBC content encryption.
    const CmsPtr cms(CMS_encrypt(
        nullptr, input.get(), EVP_aes_256_cbc(), CMS_BINARY | CMS_PARTIAL | CMS_STREAM));
    if (cms == nullptr) {
        throw std::runtime_error("CMS_encrypt failed");
    }
    unsigned char* const passCopy
        = static_cast<unsigned char*>(OPENSSL_memdup(password.data(), password.size()));
    if (passCopy == nullptr) {
        throw std::runtime_error("OPENSSL_memdup failed");
    }
    if (CMS_add0_recipient_password(cms.get(), -1, NID_undef, NID_undef, passCopy,
            static_cast<int>(password.size()), nullptr)
        == nullptr) {
        OPENSSL_free(passCopy);
        throw std::runtime_error("CMS_add0_recipient_password failed");
    }
    // Streams the plaintext from `input`, writing indefinite-length BER ciphertext
    // to `output` (replaces the in-memory path's CMS_final + i2d_CMS_bio).
    if (i2d_CMS_bio_stream(output.get(), cms.get(), input.get(), CMS_BINARY | CMS_STREAM) != 1) {
        throw std::runtime_error("i2d_CMS_bio_stream failed");
    }
}

Bytes unsealWithPassword(const Bytes& der, const std::string& password)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr input = makeInputBio(der);
    const BioPtr output = makeMemoryBio();
    unsealWithPasswordBio(input.get(), output.get(), password);
    return bioToBytes(output.get());
}

void unsealWithPasswordToFile(const std::filesystem::path& derPath,
    const std::filesystem::path& outPath, const std::string& password)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr input = makeReadFileBio(derPath);
    const BioPtr output = makeWriteFileBio(outPath);
    unsealWithPasswordBio(input.get(), output.get(), password);
    if (BIO_flush(output.get()) != 1) {
        throw std::runtime_error("BIO_flush failed");
    }
}

}  // namespace bazarish::cms
