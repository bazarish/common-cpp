// Bazarish project (c) 2026
#include "bazarish/Crypto.hpp"

#include "TestUtil.hpp"

#include <stdexcept>

using namespace bazarish;

int main()
{
    // Signing key: sign/verify round trip.
    const Key signing = Key::generateSigning();
    const Bytes message = {'b', 'a', 'z', 'a', 'r', 'i', 's', 'h'};
    const Bytes signature = sign(signing, message);
    // DER-encoded ECDSA P-256 signature: variable size around 70 bytes.
    CHECK(signature.size() >= 64 && signature.size() <= 72);
    CHECK(verify(signing, message, signature));

    // Tampered message and signature must fail.
    Bytes tampered = message;
    tampered[0] ^= 0x01;
    CHECK(!verify(signing, tampered, signature));
    Bytes badSignature = signature;
    badSignature[0] ^= 0x01;
    CHECK(!verify(signing, message, badSignature));

    // A different key must not verify.
    const Key other = Key::generateSigning();
    CHECK(!verify(other, message, signature));

    // Fingerprint: stable, correct shape, survives the public-only round trip.
    const std::string fingerprint = signing.fingerprint();
    CHECK(fingerprint.size() == kFingerprintTextLength);
    const Key publicOnly = Key::fromPublicDer(signing.publicDer());
    CHECK(!publicOnly.hasPrivate());
    CHECK(publicOnly.fingerprint() == fingerprint);

    // Private PEM round trip preserves the identity.
    const Key restored = Key::fromPrivatePem(signing.privatePem());
    CHECK(restored.hasPrivate());
    CHECK(restored.fingerprint() == fingerprint);
    CHECK(verify(restored, message, signature));

    // A public-only key cannot sign or export a private PEM.
    CHECK_THROWS(sign(publicOnly, message));
    CHECK_THROWS(publicOnly.privatePem());

    // Sealing key generation and round trips.
    const Key sealing = Key::generateSealing();
    CHECK(sealing.hasPrivate());
    CHECK(sealing.fingerprint() != fingerprint);
    const Key sealingPublic = Key::fromPublicDer(sealing.publicDer());
    CHECK(sealingPublic.fingerprint() == sealing.fingerprint());

    // Post-quantum signing key: ML-DSA-65 round trip.
    const Key pq = Key::generateSigningPq();
    CHECK(pq.isA("ML-DSA-65"));
    CHECK(!pq.isA("EC"));
    const Bytes pqSignature = sign(pq, message);
    CHECK(pqSignature.size() == 3309);
    CHECK(verify(pq, message, pqSignature));
    CHECK(!verify(pq, tampered, pqSignature));
    const Key pqPublic = Key::fromPublicDer(pq.publicDer());
    CHECK(verify(pqPublic, message, pqSignature));
    const Key pqRestored = Key::fromPrivatePem(pq.privatePem());
    CHECK(pqRestored.fingerprint() == pq.fingerprint());

    // Hybrid identity: fingerprint covers both keys and survives the
    // private PEM round trip.
    const Identity identity = Identity::generate();
    CHECK(identity.fingerprint().size() == kFingerprintTextLength);
    CHECK(identity.fingerprint()
        == hybridFingerprint(identity.classical().publicDer(), identity.pq().publicDer()));
    CHECK(identity.fingerprint() != identity.classical().fingerprint());
    const Identity restoredIdentity = Identity::fromPrivatePem(identity.privatePem());
    CHECK(restoredIdentity.fingerprint() == identity.fingerprint());
    // Mismatched key types are rejected.
    CHECK_THROWS(Identity(Key::generateSigningPq(), Key::generateSigning()));

    // SHA-256 against a known vector: sha256("abc").
    const Bytes abc = {'a', 'b', 'c'};
    CHECK(toHex(sha256(abc))
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    return 0;
}
