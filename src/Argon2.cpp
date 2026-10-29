// Bazarish project (c) 2026
#include "bazarish/Argon2.hpp"

#include <openssl/kdf.h>
#include <openssl/params.h>

#include <stdexcept>

namespace bazarish {

Bytes argon2id(const Bytes& pass, const Bytes& salt, const Argon2Cost& cost, const std::size_t outBytes)
{
    EVP_KDF* const kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (kdf == nullptr) {
        throw std::runtime_error("this OpenSSL has no Argon2id");
    }
    EVP_KDF_CTX* const ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == nullptr) {
        throw std::runtime_error("Argon2id could not start");
    }
    std::uint32_t memory = cost.memoryKiB;
    std::uint32_t passes = cost.passes;
    std::uint32_t lanes = cost.lanes;
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            "pass", const_cast<unsigned char*>(pass.data()), pass.size()),
        OSSL_PARAM_construct_octet_string(
            "salt", const_cast<unsigned char*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_uint("memcost", &memory),
        OSSL_PARAM_construct_uint("iter", &passes),
        OSSL_PARAM_construct_uint("lanes", &lanes),
        OSSL_PARAM_construct_uint("threads", &lanes),
        OSSL_PARAM_construct_end(),
    };
    Bytes derived(outBytes);
    const int ok = EVP_KDF_derive(ctx, derived.data(), derived.size(), params);
    EVP_KDF_CTX_free(ctx);
    if (ok <= 0) {
        throw std::runtime_error("Argon2id failed");
    }
    return derived;
}

}  // namespace bazarish
