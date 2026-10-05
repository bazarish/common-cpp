// Bazarish project (c) 2026
#include "bazarish/Crypto.hpp"

#include "TestUtil.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>

using namespace bazarish;

int main()
{
    const Key signing = Key::generateSigning();
    const Bytes message = {'b', 'a', 'z', 'a', 'r', 'i', 's', 'h'};
    const Bytes signature = sign(signing, message);
    // DER-encoded ECDSA P-256 signature: variable size around 70 bytes.
    CHECK(signature.size() >= 64 && signature.size() <= 72);
    CHECK(verify(signing, message, signature));

    Bytes tampered = message;
    tampered[0] ^= 0x01;
    CHECK(!verify(signing, tampered, signature));
    Bytes badSignature = signature;
    badSignature[0] ^= 0x01;
    CHECK(!verify(signing, message, badSignature));

    // A different key must not verify.
    const Key other = Key::generateSigning();
    CHECK(!verify(other, message, signature));

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

    const Key sealing = Key::generateSealing();
    CHECK(sealing.hasPrivate());
    CHECK(sealing.fingerprint() != fingerprint);
    const Key sealingPublic = Key::fromPublicDer(sealing.publicDer());
    CHECK(sealingPublic.fingerprint() == sealing.fingerprint());

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

    // Hybrid identity: fingerprint covers both keys and survives the private PEM round trip.
    const Identity identity = Identity::generate();
    CHECK(identity.fingerprint().size() == kFingerprintTextLength);
    CHECK(identity.fingerprint()
        == hybridFingerprint(identity.classical().publicDer(), identity.pq().publicDer()));
    CHECK(identity.fingerprint() != identity.classical().fingerprint());
    const Identity restoredIdentity = Identity::fromPrivatePem(identity.privatePem());
    CHECK(restoredIdentity.fingerprint() == identity.fingerprint());
    CHECK_THROWS(Identity(Key::generateSigningPq(), Key::generateSigning()));

    const std::string passphrase = "correct horse battery staple";
    const std::string encryptedPem = signing.privatePem(passphrase);
    CHECK(encryptedPem != signing.privatePem());
    CHECK(encryptedPem.find("ENCRYPTED") != std::string::npos);
    const Key fromEncrypted = Key::fromPrivatePem(encryptedPem, passphrase);
    CHECK(fromEncrypted.fingerprint() == fingerprint);
    CHECK_THROWS(Key::fromPrivatePem(encryptedPem, "wrong"));
    // An encrypted PEM read with no passphrase must not silently succeed.
    CHECK_THROWS(Key::fromPrivatePem(encryptedPem));

    const std::string encryptedIdentityPem = identity.privatePem(passphrase);
    const Identity fromEncryptedIdentity
        = Identity::fromPrivatePem(encryptedIdentityPem, passphrase);
    CHECK(fromEncryptedIdentity.fingerprint() == identity.fingerprint());
    CHECK_THROWS(Identity::fromPrivatePem(encryptedIdentityPem, "wrong"));

    const Bytes abc = {'a', 'b', 'c'};
    CHECK(toHex(sha256(abc))
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    {
        Bytes blob;
        for (int i = 0; i < 200000; ++i) {
            blob.push_back(static_cast<unsigned char>(i * 7 + 3));
        }
        const std::filesystem::path tmp
            = std::filesystem::temp_directory_path() / "bz-test-sha256file.bin";
        {
            std::ofstream out(tmp, std::ios::binary);
            out.write(reinterpret_cast<const char*>(blob.data()),
                static_cast<std::streamsize>(blob.size()));
        }
        CHECK(sha256File(tmp) == sha256(blob));
        std::filesystem::remove(tmp);
        CHECK_THROWS(sha256File(std::filesystem::temp_directory_path() / "bz-no-such-file.bin"));
    }

    {
        const Bytes key(kAeadKeyBytes, 0x11);
        const Bytes nonce(kAeadNonceBytes, 0x22);
        const Bytes plain = {'c', 'a', 'l', 'l', ' ', 'm', 'e', 'd', 'i', 'a'};
        const Bytes sealed = aeadSeal(key, nonce, plain);
        CHECK(sealed.size() == plain.size() + kAeadTagBytes);
        CHECK(sealed != plain);
        const std::optional<Bytes> opened = aeadOpen(key, nonce, sealed);
        CHECK(opened.has_value());
        CHECK(opened.value() == plain);

        Bytes tampered = sealed;
        tampered[0] ^= 0x01;
        CHECK(!aeadOpen(key, nonce, tampered).has_value());

        Bytes otherKey = key;
        otherKey[31] ^= 0x01;
        CHECK(!aeadOpen(otherKey, nonce, sealed).has_value());
        Bytes otherNonce = nonce;
        otherNonce[0] ^= 0x01;
        CHECK(!aeadOpen(key, otherNonce, sealed).has_value());

        const Bytes emptySealed = aeadSeal(key, nonce, Bytes{});
        CHECK(emptySealed.size() == kAeadTagBytes);
        const std::optional<Bytes> emptyOpened = aeadOpen(key, nonce, emptySealed);
        CHECK(emptyOpened.has_value() && emptyOpened.value().empty());

        CHECK(!aeadOpen(key, nonce, Bytes(kAeadTagBytes - 1, 0)).has_value());

        CHECK_THROWS(aeadSeal(Bytes(31, 0), nonce, plain));
        CHECK_THROWS(aeadSeal(key, Bytes(11, 0), plain));
    }

    return 0;
}
