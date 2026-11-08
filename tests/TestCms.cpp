// Bazarish project (c) 2026
#include "bazarish/Cms.hpp"

#include "TestUtil.hpp"

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>

using namespace bazarish;

namespace {

// An envelope like ours, but with the key derivation cost the sender chose.
Bytes envelopeCosting(const int iterations, const std::string& password, const Bytes& plain)
{
    BIO* const input = BIO_new_mem_buf(plain.data(), static_cast<int>(plain.size()));
    CMS_ContentInfo* const cms
        = CMS_encrypt(nullptr, input, EVP_aes_256_cbc(), CMS_BINARY | CMS_PARTIAL);
    unsigned char* const copy
        = static_cast<unsigned char*>(OPENSSL_memdup(password.data(), password.size()));
    CHECK(cms != nullptr && copy != nullptr);
    CHECK(CMS_add0_recipient_password(cms, iterations, NID_undef, NID_undef, copy,
              static_cast<int>(password.size()), nullptr)
        != nullptr);
    CHECK(CMS_final(cms, input, nullptr, CMS_BINARY) == 1);
    unsigned char* der = nullptr;
    const int length = i2d_CMS_ContentInfo(cms, &der);
    CHECK(length > 0);
    const Bytes out(der, der + length);
    OPENSSL_free(der);
    CMS_ContentInfo_free(cms);
    BIO_free(input);
    return out;
}

constexpr int kOurCost = 2048;
constexpr int kCostlierThanOurs = 4096;

}  // namespace

int main()
{
    const std::string password = "open sesame";
    const Bytes secret = {'b', 'a', 'c', 'k', 'u', 'p'};
    const Bytes passEnvelope = cms::sealWithPassword(secret, password);
    CHECK(!passEnvelope.empty());
    CHECK(cms::unsealWithPassword(passEnvelope, password) == secret);
    CHECK_THROWS(cms::unsealWithPassword(passEnvelope, "guess"));
    CHECK_THROWS(cms::sealWithPassword(secret, ""));
    CHECK(cms::unsealWithPassword(envelopeCosting(kOurCost, password, secret), password) == secret);
    CHECK_THROWS(cms::unsealWithPassword(
        envelopeCosting(kCostlierThanOurs, password, secret), password));

    {
        Bytes bigSecret;
        for (int i = 0; i < 100000; ++i) {
            bigSecret.push_back(static_cast<unsigned char>(i));
        }
        CHECK(cms::unsealWithPassword(cms::sealWithPassword(bigSecret, password), password)
            == bigSecret);
    }

    {
        constexpr std::size_t kAesBlock = 16;  // PKCS#7 padding adds 1..16 bytes
        Bytes bigPlain;
        for (int i = 0; i < 100000; ++i) {
            bigPlain.push_back(static_cast<unsigned char>(i * 11 + 5));
        }
        const std::filesystem::path dir = testutil::freshDir("seal");
        const std::filesystem::path plainPath = dir / "seal.in";
        const std::filesystem::path contentPath = dir / "seal.content";
        {
            std::ofstream out(plainPath, std::ios::binary);
            out.write(reinterpret_cast<const char*>(bigPlain.data()),
                static_cast<std::streamsize>(bigPlain.size()));
        }
        const auto sealed = [&](const std::string& secret) {
            std::ifstream in(plainPath, std::ios::binary);
            return cms::sealWithPasswordDetached(
                [&in](const ByteBuffer buffer) {
                    in.read(reinterpret_cast<char*>(buffer.data()),
                        static_cast<std::streamsize>(buffer.size()));
                    return static_cast<std::size_t>(in.gcount());
                },
                contentPath, secret);
        };
        const Bytes header = sealed(password);
        const std::uintmax_t contentBytes = std::filesystem::file_size(contentPath);
        CHECK(contentBytes == (bigPlain.size() / kAesBlock + 1) * kAesBlock);
        CHECK(header.size() < bigPlain.size());

        const auto unsealed = [&](const Bytes& envelope, const std::string& secret) {
            Bytes plain;
            cms::unsealWithPasswordDetached(envelope, contentPath, secret,
                [&plain](const ByteView data) { plain.insert(plain.end(), data.begin(), data.end()); });
            return plain;
        };
        CHECK(unsealed(header, password) == bigPlain);
        CHECK_THROWS(unsealed(header, "guess"));
        CHECK_THROWS(unsealed(header, ""));
        CHECK_THROWS(unsealed(cms::sealWithPassword(bigPlain, password), password));

        std::filesystem::resize_file(contentPath, contentBytes - kAesBlock);
        CHECK_THROWS(unsealed(header, password));

        CHECK_THROWS(sealed(""));
        std::filesystem::remove_all(dir);
    }

    return 0;
}
