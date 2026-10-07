// Bazarish project (c) 2026
#include "bazarish/Hybrid.hpp"

#include "TestUtil.hpp"

#include <cstddef>
#include <exception>
#include <stdexcept>
#include <string>

using namespace bazarish;

namespace {

nlohmann::json decode(const Bytes& frame)
{
    return nlohmann::json::from_cbor(
        frame, true, true, nlohmann::json::cbor_tag_handler_t::error);
}

Bytes encode(const nlohmann::json& frame)
{
    return nlohmann::json::to_cbor(frame);
}

Bytes bytesOf(const nlohmann::json& value)
{
    const nlohmann::json::binary_t& binary = value.get_binary();
    return Bytes(binary.begin(), binary.end());
}

}  // namespace

int main()
{
    const Identity identity = Identity::generate();
    CHECK(identity.classical().isA(kClassicalSigningAlgorithm));
    CHECK(identity.pq().isA(kPqSigningAlgorithm));

    const nlohmann::json body = {{"v", 1}, {"hello", "world"}, {"n", 42}};
    const Bytes frame = hybrid::signJson(body, identity);
    CHECK(!frame.empty());

    const hybrid::VerifiedJson verified = hybrid::verifyJson(frame);
    CHECK(verified.body == body);
    CHECK(verified.identityFingerprint == identity.fingerprint());
    CHECK(verified.signerClassicalDer == identity.classical().publicDer());
    CHECK(verified.signerPqDer == identity.pq().publicDer());

    CHECK_THROWS(hybrid::verifyJson(Bytes{0x00, 0x01, 0x02}));
    CHECK_THROWS(hybrid::verifyJson(Bytes(
        frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(frame.size() / 2))));

    {
        nlohmann::json tampered = decode(frame);
        Bytes bodyBytes = bytesOf(tampered.at("body"));
        bodyBytes[0] ^= 0x01;
        tampered["body"] = nlohmann::json::binary(bodyBytes);
        CHECK_THROWS(hybrid::verifyJson(encode(tampered)));
    }
    {
        nlohmann::json tampered = decode(frame);
        Bytes signature = bytesOf(tampered.at("c").at("sig"));
        signature[0] ^= 0x01;
        tampered["c"]["sig"] = nlohmann::json::binary(signature);
        CHECK_THROWS(hybrid::verifyJson(encode(tampered)));
    }
    {
        nlohmann::json tampered = decode(frame);
        Bytes signature = bytesOf(tampered.at("q").at("sig"));
        signature[0] ^= 0x01;
        tampered["q"]["sig"] = nlohmann::json::binary(signature);
        CHECK_THROWS(hybrid::verifyJson(encode(tampered)));
    }

    {
        nlohmann::json downgraded = decode(frame);
        downgraded["q"]["pub"] = nlohmann::json::binary(Key::generateSigning().publicDer());
        bool refusedOnKeyType = false;
        try {
            hybrid::verifyJson(encode(downgraded));
        } catch (const std::exception& error) {
            refusedOnKeyType
                = std::string(error.what()).find("pq key is not ML-DSA-65") != std::string::npos;
        }
        CHECK(refusedOnKeyType);
    }

    {
        const Identity other = Identity::generate();
        const nlohmann::json otherFrame = decode(hybrid::signJson(body, other));
        nlohmann::json spliced = decode(frame);
        spliced["q"] = otherFrame.at("q");
        CHECK_THROWS(hybrid::verifyJson(encode(spliced)));
        spliced = decode(frame);
        spliced["c"] = otherFrame.at("c");
        CHECK_THROWS(hybrid::verifyJson(encode(spliced)));
    }

    {
        nlohmann::json wrongVersion = decode(frame);
        wrongVersion["v"] = hybrid::kFrameVersion + 1;
        CHECK_THROWS(hybrid::verifyJson(encode(wrongVersion)));
        nlohmann::json wrongAlgorithm = decode(frame);
        wrongAlgorithm["c"]["alg"] = "ECDSA";
        CHECK_THROWS(hybrid::verifyJson(encode(wrongAlgorithm)));
    }

    const Key sealing = Key::generateSealing();
    CHECK(sealing.isA(kClassicalSealingAlgorithm));
    CHECK(sealing.kem().isA(kPqKemAlgorithm));

    const Key sealingPublic = Key::fromPublicDer(sealing.publicDer());
    const Bytes plaintext = {'s', 'e', 'a', 'l', 'e', 'd'};
    const Bytes envelope = hybrid::seal(plaintext, sealingPublic);
    CHECK(!envelope.empty());
    CHECK(hybrid::unseal(envelope, sealing) == plaintext);
    CHECK(hybrid::seal(plaintext, sealingPublic) != envelope);

    CHECK_THROWS(hybrid::unseal(envelope, Key::generateSealing()));
    CHECK_THROWS(hybrid::unseal(envelope, sealingPublic));
    CHECK_THROWS(hybrid::seal(plaintext, Key::generateSigning()));
    CHECK_THROWS(hybrid::unseal(Bytes{0x00, 0x01, 0x02}, sealing));

    {
        Bytes corrupted = envelope;
        corrupted[corrupted.size() - 1] ^= 0x01;
        CHECK_THROWS(hybrid::unseal(corrupted, sealing));
    }
    {
        nlohmann::json tampered = decode(envelope);
        Bytes ephemeral = bytesOf(tampered.at("eph"));
        ephemeral[0] ^= 0x01;
        tampered["eph"] = nlohmann::json::binary(ephemeral);
        CHECK_THROWS(hybrid::unseal(encode(tampered), sealing));
    }
    {
        nlohmann::json tampered = decode(envelope);
        Bytes kemCiphertext = bytesOf(tampered.at("kem"));
        kemCiphertext[0] ^= 0x01;
        tampered["kem"] = nlohmann::json::binary(kemCiphertext);
        CHECK_THROWS(hybrid::unseal(encode(tampered), sealing));
    }
    {
        nlohmann::json tampered = decode(envelope);
        Bytes nonce = bytesOf(tampered.at("n"));
        nonce[0] ^= 0x01;
        tampered["n"] = nlohmann::json::binary(nonce);
        CHECK_THROWS(hybrid::unseal(encode(tampered), sealing));
    }
    {
        nlohmann::json wrongVersion = decode(envelope);
        wrongVersion["v"] = hybrid::kFrameVersion + 1;
        CHECK_THROWS(hybrid::unseal(encode(wrongVersion), sealing));
    }

    const Bytes empty;
    CHECK(hybrid::unseal(hybrid::seal(empty, sealingPublic), sealing) == empty);

    Bytes large(100000);
    for (std::size_t i = 0; i < large.size(); ++i) {
        large[i] = static_cast<unsigned char>(i * 7 + 3);
    }
    CHECK(hybrid::unseal(hybrid::seal(large, sealingPublic), sealing) == large);

    return 0;
}
