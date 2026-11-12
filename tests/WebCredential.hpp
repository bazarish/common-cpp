// Bazarish project (c) 2026
#pragma once

#include "TestUtil.hpp"

#include <bazarish/Tls.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdio>
#include <filesystem>
#include <memory>

namespace testutil {

inline constexpr long kWebCertificateSeconds = 24 * 60 * 60;

template <auto Free>
struct OpenSslFreer {
    template <class Handle>
    void operator()(Handle* const handle) const
    {
        Free(handle);
    }
};

using PkeyPtr = std::unique_ptr<EVP_PKEY, OpenSslFreer<&EVP_PKEY_free>>;
using CertificatePtr = std::unique_ptr<X509, OpenSslFreer<&X509_free>>;
using FilePtr = std::unique_ptr<std::FILE, OpenSslFreer<&std::fclose>>;

// What a web front shows: ECDSA P-256 over SHA-256, which a browser's handshake accepts.
inline bazarish::tls::Credential webCredential(const std::filesystem::path& dir)
{
    const PkeyPtr key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
    CHECK(key != nullptr);
    const CertificatePtr certificate(X509_new());
    CHECK(certificate != nullptr);
    CHECK(X509_set_version(certificate.get(), X509_VERSION_3) == 1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0) != nullptr);
    CHECK(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), kWebCertificateSeconds)
        != nullptr);
    X509_NAME* const name = X509_get_subject_name(certificate.get());
    CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
              reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0)
        == 1);
    CHECK(X509_set_issuer_name(certificate.get(), name) == 1);
    CHECK(X509_set_pubkey(certificate.get(), key.get()) == 1);
    CHECK(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0);

    bazarish::tls::Credential credential;
    credential.certificate = dir / "web.crt";
    credential.key = dir / "web.key";
    {
        const FilePtr out(std::fopen(credential.certificate.string().c_str(), "wb"));
        CHECK(out != nullptr);
        CHECK(PEM_write_X509(out.get(), certificate.get()) == 1);
    }
    {
        const FilePtr out(std::fopen(credential.key.string().c_str(), "wb"));
        CHECK(out != nullptr);
        CHECK(PEM_write_PrivateKey(out.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr)
            == 1);
    }
    return credential;
}

}  // namespace testutil
