// Bazarish project (c) 2026
#include "bazarish/Cms.hpp"

#include "TestUtil.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>

using namespace bazarish;

int main()
{
    const std::string password = "open sesame";
    const Bytes secret = {'b', 'a', 'c', 'k', 'u', 'p'};
    const Bytes passEnvelope = cms::sealWithPassword(secret, password);
    CHECK(!passEnvelope.empty());
    CHECK(cms::unsealWithPassword(passEnvelope, password) == secret);
    CHECK_THROWS(cms::unsealWithPassword(passEnvelope, "guess"));
    CHECK_THROWS(cms::sealWithPassword(secret, ""));

    {
        Bytes bigSecret;
        for (int i = 0; i < 100000; ++i) {
            bigSecret.push_back(static_cast<unsigned char>(i));
        }
        CHECK(cms::unsealWithPassword(cms::sealWithPassword(bigSecret, password), password)
            == bigSecret);
    }

    {
        constexpr std::size_t kAesBlock = 16;  // AES block, PKCS#7 padding adds 1..16 bytes
        Bytes bigPlain;
        for (int i = 0; i < 100000; ++i) {
            bigPlain.push_back(static_cast<unsigned char>(i * 11 + 5));
        }
        const std::filesystem::path plainPath
            = std::filesystem::temp_directory_path() / "bz-test-seal.in";
        const std::filesystem::path contentPath
            = std::filesystem::temp_directory_path() / "bz-test-seal.content";
        {
            std::ofstream out(plainPath, std::ios::binary);
            out.write(reinterpret_cast<const char*>(bigPlain.data()),
                static_cast<std::streamsize>(bigPlain.size()));
        }
        const auto sealed = [&](const std::string& secret) {
            std::ifstream in(plainPath, std::ios::binary);
            return cms::sealWithPasswordDetached(
                [&in](void* const buffer, const std::size_t size) {
                    in.read(static_cast<char*>(buffer), static_cast<std::streamsize>(size));
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
                [&plain](const void* data, const std::size_t size) {
                    const auto* const bytes = static_cast<const unsigned char*>(data);
                    plain.insert(plain.end(), bytes, bytes + size);
                });
            return plain;
        };
        CHECK(unsealed(header, password) == bigPlain);
        CHECK_THROWS(unsealed(header, "guess"));
        CHECK_THROWS(unsealed(header, ""));
        CHECK_THROWS(unsealed(cms::sealWithPassword(bigPlain, password), password));

        std::filesystem::resize_file(contentPath, contentBytes - kAesBlock);
        CHECK_THROWS(unsealed(header, password));

        CHECK_THROWS(sealed(""));
        std::filesystem::remove(plainPath);
        std::filesystem::remove(contentPath);
    }

    return 0;
}
