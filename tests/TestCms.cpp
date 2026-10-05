// Bazarish project (c) 2026
#include "bazarish/Cms.hpp"

#include "TestUtil.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>

using namespace bazarish;

int main()
{
    const Key user = Key::generateSigning();
    const nlohmann::json body = {{"v", 1}, {"hello", "world"}, {"n", 42}};
    const Bytes der = cms::signJson(body, user);
    CHECK(!der.empty());

    const cms::VerifiedJson verified = cms::verifyJson(der);
    CHECK(verified.body == body);
    CHECK(verified.signerFingerprint == user.fingerprint());

    const std::string marker = "world";
    const auto markerStart = std::search(der.begin(), der.end(), marker.begin(), marker.end());
    CHECK(markerStart != der.end());
    Bytes corrupted = der;
    corrupted[static_cast<std::size_t>(markerStart - der.begin())] ^= 0x01;
    CHECK_THROWS(cms::verifyJson(corrupted));
    CHECK_THROWS(cms::verifyJson(Bytes{0x00, 0x01, 0x02}));

    const Identity identity = Identity::generate();
    const Bytes hybridDer = cms::signJsonHybrid(body, identity);
    const cms::VerifiedHybridJson hybridVerified = cms::verifyJsonHybrid(hybridDer);
    CHECK(hybridVerified.body == body);
    CHECK(hybridVerified.identityFingerprint == identity.fingerprint());

    {
        const cms::VerifiedJson wrapper = cms::verifyJson(hybridDer);
        nlohmann::json tamperedWrapper = wrapper.body;
        std::string sig = tamperedWrapper.at("pq").at("sig").get<std::string>();
        sig[0] = sig[0] == 'A' ? 'B' : 'A';
        tamperedWrapper["pq"]["sig"] = sig;
        const Bytes resigned = cms::signJson(tamperedWrapper, identity.classical());
        CHECK_THROWS(cms::verifyJsonHybrid(resigned));
    }

    {
        const std::string serialized = body.dump();
        const Bytes bodyBytes(serialized.begin(), serialized.end());
        const Key ecAsPq = Key::generateSigning();
        const nlohmann::json downgraded = {
            {"body", toBase64(bodyBytes)},
            {"pq",
                {
                    {"alg", "ML-DSA-65"},
                    {"pub", toBase64(ecAsPq.publicDer())},
                    {"sig", toBase64(sign(ecAsPq, bodyBytes))},
                }},
        };
        const Bytes downgradedDer = cms::signJson(downgraded, identity.classical());
        CHECK_THROWS(cms::verifyJsonHybrid(downgradedDer));
    }

    const Key sealing = Key::generateSealing();
    const Key sealingPublic = Key::fromPublicDer(sealing.publicDer());
    const Bytes plaintext = {'s', 'e', 'a', 'l', 'e', 'd'};
    const Bytes envelope = cms::seal(plaintext, sealingPublic);
    CHECK(!envelope.empty());
    CHECK(cms::unseal(envelope, sealing) == plaintext);

    // A different key must not decrypt; ciphertext corruption must fail.
    const Key wrongKey = Key::generateSealing();
    CHECK_THROWS(cms::unseal(envelope, wrongKey));
    Bytes corruptedEnvelope = envelope;
    corruptedEnvelope[corruptedEnvelope.size() - 1] ^= 0x01;
    CHECK_THROWS(cms::unseal(corruptedEnvelope, sealing));

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
