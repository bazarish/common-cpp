// Bazarish project (c) 2026
#include "bazarish/Cms.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdexcept>

namespace {

using bazarish::Bytes;
using bazarish::Key;

// Carrier certificates exist only to transport a public key through CMS
// structures; validity is set wide so clock skew can never interfere.
constexpr long kCarrierCertValiditySeconds = 60L * 60 * 24 * 365 * 100;

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
        BIGNUM* const serialBn = BN_bin2bn(serial.data(), static_cast<int>(serial.size()), nullptr);
        ok = serialBn != nullptr
            && BN_to_ASN1_INTEGER(serialBn, X509_get_serialNumber(cert.get())) != nullptr;
        BN_free(serialBn);
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
        && X509_gmtime_adj(X509_getm_notAfter(cert.get()), kCarrierCertValiditySeconds) != nullptr
        && X509_set_pubkey(cert.get(), subjectKey.raw()) == 1;

    ok = ok && X509_sign(cert.get(), signerKey.raw(), EVP_sha256()) > 0;

    if (!ok) {
        throw std::runtime_error("carrier certificate creation failed");
    }
    return cert;
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

    STACK_OF(X509)* const signers = CMS_get0_signers(cms.get());
    if (signers == nullptr || sk_X509_num(signers) != 1) {
        sk_X509_free(signers);
        throw std::runtime_error("CMS signer extraction failed");
    }
    EVP_PKEY* const signerPubkey = X509_get0_pubkey(sk_X509_value(signers, 0));
    sk_X509_free(signers);
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

Bytes seal(const Bytes& plaintext, const Key& recipientPublicKey)
{
    // The carrier certificate is signed by a throwaway signing key;
    // only the embedded recipient public key matters.
    const Key throwaway = Key::generateSigning();
    const X509Ptr carrier = makeCarrierCert(recipientPublicKey, throwaway);

    STACK_OF(X509)* const recipients = sk_X509_new_null();
    if (recipients == nullptr || sk_X509_push(recipients, carrier.get()) <= 0) {
        sk_X509_free(recipients);
        throw std::runtime_error("recipient stack creation failed");
    }

    const BioPtr input = makeInputBio(plaintext);
    const CmsPtr cms(
        CMS_encrypt(recipients, input.get(), EVP_aes_256_gcm(), CMS_BINARY));
    sk_X509_free(recipients);
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
    return bioToBytes(output.get());
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

Bytes unsealWithPassword(const Bytes& der, const std::string& password)
{
    if (password.empty()) {
        throw std::invalid_argument("password must not be empty");
    }
    const BioPtr input = makeInputBio(der);
    const CmsPtr cms(d2i_CMS_bio(input.get(), nullptr));
    if (cms == nullptr) {
        throw std::runtime_error("d2i_CMS_bio failed");
    }
    if (CMS_decrypt_set1_password(cms.get(),
            reinterpret_cast<unsigned char*>(const_cast<char*>(password.data())),
            static_cast<int>(password.size()))
        != 1) {
        throw std::runtime_error("CMS_decrypt_set1_password failed");
    }

    const BioPtr output = makeMemoryBio();
    // The recipient key arguments are null: the password set above is the key
    // source. A wrong password surfaces here as a decrypt failure.
    if (CMS_decrypt(cms.get(), nullptr, nullptr, nullptr, output.get(), CMS_BINARY) != 1) {
        throw std::runtime_error("CMS_decrypt failed (wrong password?)");
    }
    return bioToBytes(output.get());
}

}  // namespace bazarish::cms
