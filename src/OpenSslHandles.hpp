// Bazarish project (c) 2026
#pragma once

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>

#include <memory>

namespace bazarish::ossl {

template <auto Free>
struct Freer {
    template <class Handle>
    void operator()(Handle* const handle) const
    {
        static_cast<void>(Free(handle));
    }
};

struct OpenSslFree {
    void operator()(unsigned char* const block) const { OPENSSL_free(block); }
};

using BioPtr = std::unique_ptr<BIO, Freer<&BIO_free>>;
using BioChainPtr = std::unique_ptr<BIO, Freer<&BIO_free_all>>;
using BignumPtr = std::unique_ptr<BIGNUM, Freer<&BN_free>>;
using BlockPtr = std::unique_ptr<unsigned char, OpenSslFree>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, Freer<&EVP_CIPHER_CTX_free>>;
using CmsPtr = std::unique_ptr<CMS_ContentInfo, Freer<&CMS_ContentInfo_free>>;
using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, Freer<&EVP_KDF_CTX_free>>;
using KdfPtr = std::unique_ptr<EVP_KDF, Freer<&EVP_KDF_free>>;
using Pbkdf2ParamPtr = std::unique_ptr<PBKDF2PARAM, Freer<&PBKDF2PARAM_free>>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, Freer<&EVP_MD_CTX_free>>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, Freer<&EVP_PKEY_CTX_free>>;
using X509Ptr = std::unique_ptr<X509, Freer<&X509_free>>;

}  // namespace bazarish::ossl
