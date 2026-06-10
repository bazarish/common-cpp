// Bazarish project (c) 2026
#include "bazarish/Cms.hpp"

#include "TestUtil.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>

using namespace bazarish;

int main()
{
    // SignedData round trip: body comes back intact, signer is identified.
    const Key user = Key::generateSigning();
    const nlohmann::json body = {{"v", 1}, {"hello", "world"}, {"n", 42}};
    const Bytes der = cms::signJson(body, user);
    CHECK(!der.empty());

    const cms::VerifiedJson verified = cms::verifyJson(der);
    CHECK(verified.body == body);
    CHECK(verified.signerFingerprint == user.fingerprint());

    // Corrupting the signed payload must fail verification. The JSON
    // content is embedded verbatim in the DER; flip a byte inside it.
    // (Bytes elsewhere may land in the carrier certificate's own fields,
    // which are deliberately not verified.)
    const std::string marker = "world";
    const auto markerStart = std::search(der.begin(), der.end(), marker.begin(), marker.end());
    CHECK(markerStart != der.end());
    Bytes corrupted = der;
    corrupted[static_cast<std::size_t>(markerStart - der.begin())] ^= 0x01;
    CHECK_THROWS(cms::verifyJson(corrupted));
    CHECK_THROWS(cms::verifyJson(Bytes{0x00, 0x01, 0x02}));

    // Hybrid round trip: body intact, identity fingerprint covers both keys.
    const Identity identity = Identity::generate();
    const Bytes hybridDer = cms::signJsonHybrid(body, identity);
    const cms::VerifiedHybridJson hybridVerified = cms::verifyJsonHybrid(hybridDer);
    CHECK(hybridVerified.body == body);
    CHECK(hybridVerified.identityFingerprint == identity.fingerprint());

    // A wrapper with a valid classical signature but a broken pq signature
    // must fail: flip a byte inside the base64 of the pq signature.
    {
        const cms::VerifiedJson wrapper = cms::verifyJson(hybridDer);
        nlohmann::json tamperedWrapper = wrapper.body;
        std::string sig = tamperedWrapper.at("pq").at("sig").get<std::string>();
        sig[0] = sig[0] == 'A' ? 'B' : 'A';
        tamperedWrapper["pq"]["sig"] = sig;
        const Bytes resigned = cms::signJson(tamperedWrapper, identity.classical());
        CHECK_THROWS(cms::verifyJsonHybrid(resigned));
    }

    // Downgrade: an EC key smuggled into the pq slot must fail even with
    // a consistent signature.
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

    // Envelope round trip with a sealing key.
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

    // Password-based envelope: round trips with the password and rejects the
    // wrong one. Used by the encrypted state export.
    const std::string password = "open sesame";
    const Bytes secret = {'b', 'a', 'c', 'k', 'u', 'p'};
    const Bytes passEnvelope = cms::sealWithPassword(secret, password);
    CHECK(!passEnvelope.empty());
    CHECK(cms::unsealWithPassword(passEnvelope, password) == secret);
    CHECK_THROWS(cms::unsealWithPassword(passEnvelope, "guess"));
    CHECK_THROWS(cms::sealWithPassword(secret, ""));

    return 0;
}
