// Bazarish project (c) 2026
#include "bazarish/Hmac.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <cstddef>
#include <memory>
#include <stdexcept>

namespace bazarish::service {

std::string hmacSha256Hex(const std::string& key, const std::string& data)
{
    const std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(
        EVP_MAC_fetch(nullptr, "HMAC", nullptr), &EVP_MAC_free);
    if (mac == nullptr) {
        throw std::runtime_error("HMAC: EVP_MAC_fetch failed");
    }
    const std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(
        EVP_MAC_CTX_new(mac.get()), &EVP_MAC_CTX_free);
    if (ctx == nullptr) {
        throw std::runtime_error("HMAC: EVP_MAC_CTX_new failed");
    }
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", digest, 0),
        OSSL_PARAM_construct_end(),
    };
    unsigned char out[EVP_MAX_MD_SIZE];
    std::size_t outLen = 0;
    const bool ok
        = EVP_MAC_init(ctx.get(), reinterpret_cast<const unsigned char*>(key.data()), key.size(),
              params)
            == 1
        && EVP_MAC_update(
               ctx.get(), reinterpret_cast<const unsigned char*>(data.data()), data.size())
            == 1
        && EVP_MAC_final(ctx.get(), out, &outLen, sizeof out) == 1;
    if (!ok) {
        throw std::runtime_error("HMAC computation failed");
    }
    static const char* const kHex = "0123456789abcdef";
    std::string hex;
    hex.reserve(outLen * 2);
    for (std::size_t i = 0; i < outLen; ++i) {
        hex.push_back(kHex[out[i] >> 4]);
        hex.push_back(kHex[out[i] & 0x0f]);
    }
    return hex;
}

bool constantTimeEqual(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) {
        return false;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace bazarish::service
