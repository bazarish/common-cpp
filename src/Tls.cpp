// Bazarish project (c) 2026
#include "bazarish/Tls.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/PrivateFile.hpp"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>
#include <stdexcept>

namespace fs = std::filesystem;

namespace bazarish::tls {

namespace {

constexpr const char* kCertificateName = "ops-cert.pem";
constexpr const char* kKeyName = "ops-key.pem";
constexpr const char* kSubject = "bazarish";
constexpr long kValiditySeconds = 10 * 365 * 24 * 60 * 60;
constexpr std::size_t kSerialBytes = 16;

struct X509Deleter {
    void operator()(X509* certificate) const { X509_free(certificate); }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

struct BioDeleter {
    void operator()(BIO* bio) const { BIO_free(bio); }
};
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

std::string pinOfSpki(X509* const certificate)
{
    unsigned char* der = nullptr;
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &der);
    if (length <= 0 || der == nullptr) {
        throw std::runtime_error("tls: the certificate carries no key");
    }
    const std::string pin = toHex(sha256(Bytes(der, der + length)));
    OPENSSL_free(der);
    return pin;
}

X509Ptr readCertificate(const fs::path& path)
{
    const std::string pem = readFileText(path);
    const BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) {
        throw std::runtime_error("tls: cannot read " + path.string());
    }
    X509Ptr certificate(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!certificate) {
        throw std::runtime_error("tls: " + path.string() + " is not a certificate");
    }
    return certificate;
}

X509Ptr issueSelfSigned(const Key& key)
{
    X509Ptr certificate(X509_new());
    if (!certificate) {
        throw std::runtime_error("tls: cannot make a certificate");
    }
    // X509_set_version takes the version number less one: 2 is v3.
    constexpr long kVersionV3 = 2;
    if (X509_set_version(certificate.get(), kVersionV3) != 1) {
        throw std::runtime_error("tls: cannot set the certificate version");
    }
    const Bytes serial = randomBytes(kSerialBytes);
    const std::unique_ptr<BIGNUM, decltype(&BN_free)> number(
        BN_bin2bn(serial.data(), static_cast<int>(serial.size()), nullptr), BN_free);
    if (!number
        || BN_to_ASN1_INTEGER(number.get(), X509_get_serialNumber(certificate.get())) == nullptr) {
        throw std::runtime_error("tls: cannot set the certificate serial");
    }
    if (X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0) == nullptr
        || X509_gmtime_adj(X509_getm_notAfter(certificate.get()), kValiditySeconds) == nullptr) {
        throw std::runtime_error("tls: cannot set the certificate validity");
    }
    X509_NAME* const name = X509_get_subject_name(certificate.get());
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(kSubject), -1, -1, 0)
        != 1) {
        throw std::runtime_error("tls: cannot name the certificate");
    }
    if (X509_set_issuer_name(certificate.get(), name) != 1
        || X509_set_pubkey(certificate.get(), key.raw()) != 1) {
        throw std::runtime_error("tls: cannot fill the certificate");
    }
    // Ed25519 signs the message itself, so it takes no digest.
    if (X509_sign(certificate.get(), key.raw(), nullptr) == 0) {
        throw std::runtime_error("tls: cannot sign the certificate");
    }
    return certificate;
}

std::string certificatePem(X509* const certificate)
{
    const BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio || PEM_write_bio_X509(bio.get(), certificate) != 1) {
        throw std::runtime_error("tls: cannot write the certificate");
    }
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    if (length <= 0 || data == nullptr) {
        throw std::runtime_error("tls: the certificate came out empty");
    }
    return std::string(data, static_cast<std::size_t>(length));
}

}  // namespace

Credential selfSigned(const fs::path& stateDir)
{
    Credential credential;
    credential.certificate = stateDir / kCertificateName;
    credential.key = stateDir / kKeyName;
    if (fs::exists(credential.certificate) && fs::exists(credential.key)) {
        credential.pin = pinOfCertificate(credential.certificate);
        return credential;
    }
    fs::create_directories(stateDir);
    const Key key = Key::generateSigning();
    const X509Ptr certificate = issueSelfSigned(key);
    writeFileAtomic(credential.certificate, certificatePem(certificate.get()));
    writePrivateFile(credential.key, key.privatePem());
    credential.pin = pinOfSpki(certificate.get());
    return credential;
}

std::string pinOf(SSL* const connection)
{
    const X509Ptr certificate(SSL_get1_peer_certificate(connection));
    if (!certificate) {
        return {};
    }
    return pinOfSpki(certificate.get());
}

std::string pinOfCertificate(const fs::path& certificate)
{
    return pinOfSpki(readCertificate(certificate).get());
}

}  // namespace bazarish::tls
