// Bazarish project (c) 2026
#include "bazarish/Cms.hpp"

#include "TestUtil.hpp"

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
        const Bytes bigEnvelope = cms::sealWithPassword(bigSecret, password);
        const std::filesystem::path derPath
            = std::filesystem::temp_directory_path() / "bz-test-pwri.der";
        const std::filesystem::path outPath
            = std::filesystem::temp_directory_path() / "bz-test-pwri.out";
        {
            std::ofstream out(derPath, std::ios::binary);
            out.write(reinterpret_cast<const char*>(bigEnvelope.data()),
                static_cast<std::streamsize>(bigEnvelope.size()));
        }
        cms::unsealWithPasswordToFile(derPath, outPath, password);
        Bytes recovered;
        {
            std::ifstream in(outPath, std::ios::binary);
            recovered.assign(
                (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        }
        CHECK(recovered == bigSecret);
        CHECK_THROWS(cms::unsealWithPasswordToFile(derPath, outPath, "guess"));
        CHECK_THROWS(cms::unsealWithPasswordToFile(derPath, outPath, ""));
        std::filesystem::remove(derPath);
        std::filesystem::remove(outPath);
    }

    {
        Bytes bigPlain;
        for (int i = 0; i < 100000; ++i) {
            bigPlain.push_back(static_cast<unsigned char>(i * 11 + 5));
        }
        const std::filesystem::path plainPath
            = std::filesystem::temp_directory_path() / "bz-test-seal.in";
        const std::filesystem::path cipherPath
            = std::filesystem::temp_directory_path() / "bz-test-seal.der";
        const std::filesystem::path outPath
            = std::filesystem::temp_directory_path() / "bz-test-seal.out";
        {
            std::ofstream out(plainPath, std::ios::binary);
            out.write(reinterpret_cast<const char*>(bigPlain.data()),
                static_cast<std::streamsize>(bigPlain.size()));
        }
        cms::sealWithPasswordToFile(plainPath, cipherPath, password);

        cms::unsealWithPasswordToFile(cipherPath, outPath, password);
        Bytes recovered;
        Bytes envelope;
        {
            std::ifstream fromFile(outPath, std::ios::binary);
            recovered.assign(
                (std::istreambuf_iterator<char>(fromFile)), std::istreambuf_iterator<char>());
            std::ifstream cipherIn(cipherPath, std::ios::binary);
            envelope.assign(
                (std::istreambuf_iterator<char>(cipherIn)), std::istreambuf_iterator<char>());
        }
        CHECK(recovered == bigPlain);
        // ...and the streamed envelope is a valid CMS that the in-memory path reads too.
        CHECK(cms::unsealWithPassword(envelope, password) == bigPlain);

        CHECK_THROWS(cms::sealWithPasswordToFile(plainPath, cipherPath, ""));
        std::filesystem::remove(plainPath);
        std::filesystem::remove(cipherPath);
        std::filesystem::remove(outPath);
    }

    return 0;
}
