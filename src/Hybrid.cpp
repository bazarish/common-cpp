// Bazarish project (c) 2026
#include "bazarish/Hybrid.hpp"
#include "bazarish/JsonRead.hpp"
#include "bazarish/SecretBytes.hpp"

#include "OpenSslHandles.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

using bazarish::Bytes;
using bazarish::Key;
using bazarish::SecretBytes;

constexpr const char* kSignContext = "bazarish-composite-sig-v1";
constexpr const char* kSealContext = "bazarish-composite-seal-v1";
constexpr std::size_t kX25519SharedSecretBytes = 32;

using PkeyPtr = bazarish::KeyPtr;
using bazarish::ossl::PkeyCtxPtr;


void append(Bytes& target, const Bytes& tail)
{
    target.insert(target.end(), tail.begin(), tail.end());
}

Bytes contextBytes(const char* const context)
{
    const unsigned char* const begin = reinterpret_cast<const unsigned char*>(context);
    return Bytes(begin, begin + std::strlen(context));
}

Bytes bytesOf(const nlohmann::json::binary_t& value)
{
    return Bytes(value.begin(), value.end());
}

nlohmann::json parseFrame(const Bytes& frame)
{
    const nlohmann::json parsed = bazarish::parseCbor(frame);
    if (!parsed.is_object()) {
        throw std::runtime_error("frame is not a CBOR map");
    }
    return parsed;
}

void requireVersion(const nlohmann::json& frame)
{
    const int version = frame.at("v").get<int>();
    if (version != bazarish::hybrid::kFrameVersion) {
        throw std::runtime_error("frame is version " + std::to_string(version)
            + ", this build reads version "
            + std::to_string(bazarish::hybrid::kFrameVersion));
    }
}

// The message names both public keys: swapping either half breaks the other's signature.
Bytes signedMessage(
    const Bytes& classicalPublicDer, const Bytes& pqPublicDer, const Bytes& body)
{
    Bytes keys = classicalPublicDer;
    append(keys, pqPublicDer);
    Bytes message = contextBytes(kSignContext);
    append(message, bazarish::keyDigest(keys));
    append(message, body);
    return message;
}

Bytes sealTranscript(const Bytes& kemCiphertext, const Bytes& ephemeralPublic,
    const Bytes& recipientPublicDer, const Bytes& kid)
{
    Bytes transcript = kemCiphertext;
    append(transcript, ephemeralPublic);
    append(transcript, recipientPublicDer);
    append(transcript, bazarish::sha256(kid));
    return transcript;
}

Bytes kidOf(const nlohmann::json& frame)
{
    const Bytes kid = bytesOf(frame.at("kid").get_binary());
    if (kid.size() > bazarish::hybrid::kMaxSealKidBytes) {
        throw std::runtime_error("a sealed frame names a key id longer than any key has");
    }
    return kid;
}

PkeyPtr generateEphemeral()
{
    PkeyPtr key(EVP_PKEY_Q_keygen(nullptr, nullptr, bazarish::kClassicalSealingAlgorithm));
    if (key == nullptr) {
        throw std::runtime_error("ephemeral X25519 keygen failed");
    }
    return key;
}

Bytes rawPublicKey(EVP_PKEY* const key)
{
    std::size_t size = 0;
    if (EVP_PKEY_get_raw_public_key(key, nullptr, &size) != 1) {
        throw std::runtime_error("EVP_PKEY_get_raw_public_key sizing failed");
    }
    Bytes raw(size);
    if (EVP_PKEY_get_raw_public_key(key, raw.data(), &size) != 1) {
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed");
    }
    raw.resize(size);
    return raw;
}

PkeyPtr publicKeyFromRaw(const Bytes& raw)
{
    PkeyPtr key(EVP_PKEY_new_raw_public_key_ex(
        nullptr, bazarish::kClassicalSealingAlgorithm, nullptr, raw.data(), raw.size()));
    if (key == nullptr) {
        throw std::runtime_error("ephemeral public key does not parse");
    }
    return key;
}

SecretBytes agree(EVP_PKEY* const ours, EVP_PKEY* const theirs)
{
    const PkeyCtxPtr ctx(EVP_PKEY_CTX_new(ours, nullptr));
    if (ctx == nullptr || EVP_PKEY_derive_init(ctx.get()) != 1
        || EVP_PKEY_derive_set_peer(ctx.get(), theirs) != 1) {
        throw std::runtime_error("X25519 derive init failed");
    }
    std::size_t size = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &size) != 1) {
        throw std::runtime_error("X25519 derive sizing failed");
    }
    SecretBytes secret(size);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &size) != 1) {
        throw std::runtime_error("X25519 derive failed");
    }
    secret.resize(size);
    if (secret.size() != kX25519SharedSecretBytes) {
        throw std::runtime_error("X25519 shared secret has unexpected size");
    }
    return secret;
}

struct Encapsulation {
    Bytes ciphertext;
    SecretBytes sharedSecret;
};

Encapsulation encapsulate(EVP_PKEY* const recipientKem)
{
    const PkeyCtxPtr ctx(EVP_PKEY_CTX_new(recipientKem, nullptr));
    if (ctx == nullptr || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) != 1) {
        throw std::runtime_error("ML-KEM encapsulate init failed");
    }
    std::size_t ciphertextSize = 0;
    std::size_t secretSize = 0;
    if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &ciphertextSize, nullptr, &secretSize) != 1) {
        throw std::runtime_error("ML-KEM encapsulate sizing failed");
    }
    Encapsulation result{Bytes(ciphertextSize), SecretBytes(secretSize)};
    if (EVP_PKEY_encapsulate(ctx.get(), result.ciphertext.data(), &ciphertextSize,
            result.sharedSecret.data(), &secretSize)
        != 1) {
        throw std::runtime_error("ML-KEM encapsulate failed");
    }
    result.ciphertext.resize(ciphertextSize);
    result.sharedSecret.resize(secretSize);
    return result;
}

SecretBytes decapsulate(EVP_PKEY* const recipientKem, const Bytes& ciphertext)
{
    const PkeyCtxPtr ctx(EVP_PKEY_CTX_new(recipientKem, nullptr));
    if (ctx == nullptr || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) != 1) {
        throw std::runtime_error("ML-KEM decapsulate init failed");
    }
    std::size_t secretSize = 0;
    if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &secretSize, ciphertext.data(), ciphertext.size())
        != 1) {
        throw std::runtime_error("ML-KEM decapsulate sizing failed");
    }
    SecretBytes secret(secretSize);
    if (EVP_PKEY_decapsulate(
            ctx.get(), secret.data(), &secretSize, ciphertext.data(), ciphertext.size())
        != 1) {
        throw std::runtime_error("ML-KEM decapsulate failed");
    }
    secret.resize(secretSize);
    return secret;
}

SecretBytes deriveSealKey(
    const SecretBytes& pqSecret, const SecretBytes& classicalSecret, const Bytes& transcript)
{
    SecretBytes material(pqSecret.size() + classicalSecret.size());
    std::copy(pqSecret.bytes().begin(), pqSecret.bytes().end(), material.data());
    std::copy(classicalSecret.bytes().begin(), classicalSecret.bytes().end(),
        material.data() + pqSecret.size());
    return SecretBytes(
        bazarish::hkdfSha256(material.bytes(), transcript, kSealContext, bazarish::kAeadKeyBytes));
}

}  // namespace

namespace bazarish::hybrid {

Bytes signJson(const nlohmann::json& body, const Identity& identity)
{
    const std::string serialized = body.dump();
    const Bytes bodyBytes(serialized.begin(), serialized.end());
    const Bytes classicalPublicDer = identity.classical().publicDer();
    const Bytes pqPublicDer = identity.pq().publicDer();
    const Bytes message = signedMessage(classicalPublicDer, pqPublicDer, bodyBytes);

    const nlohmann::json frame = {
        {"v", kFrameVersion},
        {"body", nlohmann::json::binary(bodyBytes)},
        {"c",
            {
                {"alg", kClassicalSigningAlgorithm},
                {"pub", nlohmann::json::binary(classicalPublicDer)},
                {"sig", nlohmann::json::binary(sign(identity.classical(), message))},
            }},
        {"q",
            {
                {"alg", kPqSigningAlgorithm},
                {"pub", nlohmann::json::binary(pqPublicDer)},
                {"sig", nlohmann::json::binary(sign(identity.pq(), message))},
            }},
    };
    return nlohmann::json::to_cbor(frame);
}

VerifiedJson verifyJson(const Bytes& frame)
{
    const nlohmann::json parsed = parseFrame(frame);
    requireVersion(parsed);

    const nlohmann::json& classical = parsed.at("c");
    const nlohmann::json& pq = parsed.at("q");
    if (classical.at("alg").get<std::string>() != kClassicalSigningAlgorithm) {
        throw std::runtime_error("signed frame: unexpected classical algorithm");
    }
    if (pq.at("alg").get<std::string>() != kPqSigningAlgorithm) {
        throw std::runtime_error("signed frame: unexpected pq algorithm");
    }

    const Bytes bodyBytes = bytesOf(parsed.at("body").get_binary());
    const Bytes classicalPublicDer = bytesOf(classical.at("pub").get_binary());
    const Bytes pqPublicDer = bytesOf(pq.at("pub").get_binary());

    const Key classicalKey = Key::fromPublicDer(classicalPublicDer);
    if (!classicalKey.isA(kClassicalSigningAlgorithm)) {
        throw std::runtime_error("signed frame: classical signer is not Ed25519");
    }
    const Key pqKey = Key::fromPublicDer(pqPublicDer);
    if (!pqKey.isA(kPqSigningAlgorithm)) {
        throw std::runtime_error("signed frame: pq key is not ML-DSA-65");
    }

    const Bytes message = signedMessage(classicalPublicDer, pqPublicDer, bodyBytes);
    if (!verify(classicalKey, message, bytesOf(classical.at("sig").get_binary()))) {
        throw std::runtime_error("signed frame: classical signature verification failed");
    }
    if (!verify(pqKey, message, bytesOf(pq.at("sig").get_binary()))) {
        throw std::runtime_error("signed frame: pq signature verification failed");
    }

    return VerifiedJson{
        parseJson(bodyBytes),
        hybridFingerprint(classicalPublicDer, pqPublicDer),
        classicalPublicDer,
        pqPublicDer,
    };
}

bool isSealingKey(const Key& key)
{
    return key.hasKem() && key.isA(kClassicalSealingAlgorithm) && key.kem().isA(kPqKemAlgorithm);
}

Bytes seal(const Bytes& plaintext, const Key& recipientPublicKey, const Bytes& kid)
{
    if (kid.size() > kMaxSealKidBytes) {
        throw std::logic_error("a key id is at most " + std::to_string(kMaxSealKidBytes) + " bytes");
    }
    if (!isSealingKey(recipientPublicKey)) {
        throw std::logic_error("sealing requires an X25519 and ML-KEM-768 recipient key");
    }

    Encapsulation encapsulated = encapsulate(recipientPublicKey.kem().raw());
    const PkeyPtr ephemeral = generateEphemeral();
    const Bytes ephemeralPublic = rawPublicKey(ephemeral.get());
    SecretBytes classicalSecret = agree(ephemeral.get(), recipientPublicKey.raw());
    const Bytes transcript = sealTranscript(
        encapsulated.ciphertext, ephemeralPublic, recipientPublicKey.publicDer(), kid);

    SecretBytes key = deriveSealKey(encapsulated.sharedSecret, classicalSecret, transcript);
    encapsulated.sharedSecret.clear();
    classicalSecret.clear();

    const Bytes nonce = randomBytes(kAeadNonceBytes);
    const Bytes ciphertext = aeadSeal(key.bytes(), nonce, plaintext);
    key.clear();

    const nlohmann::json frame = {
        {"v", kFrameVersion},
        {"kid", nlohmann::json::binary(kid)},
        {"kem", nlohmann::json::binary(encapsulated.ciphertext)},
        {"eph", nlohmann::json::binary(ephemeralPublic)},
        {"n", nlohmann::json::binary(nonce)},
        {"ct", nlohmann::json::binary(ciphertext)},
    };
    return nlohmann::json::to_cbor(frame);
}

Bytes sealedKid(const Bytes& frame)
{
    const nlohmann::json parsed = parseFrame(frame);
    requireVersion(parsed);
    return kidOf(parsed);
}

SecretBytes unseal(const Bytes& frame, const Key& recipientPrivateKey)
{
    if (!recipientPrivateKey.hasPrivate()) {
        throw std::logic_error("unsealing requires a private key");
    }
    if (!isSealingKey(recipientPrivateKey)) {
        throw std::logic_error("unsealing requires an X25519 and ML-KEM-768 key");
    }

    const nlohmann::json parsed = parseFrame(frame);
    requireVersion(parsed);
    const Bytes kid = kidOf(parsed);
    const Bytes kemCiphertext = bytesOf(parsed.at("kem").get_binary());
    const Bytes ephemeralPublic = bytesOf(parsed.at("eph").get_binary());
    const Bytes nonce = bytesOf(parsed.at("n").get_binary());
    const Bytes ciphertext = bytesOf(parsed.at("ct").get_binary());

    const PkeyPtr ephemeral = publicKeyFromRaw(ephemeralPublic);
    SecretBytes pqSecret = decapsulate(recipientPrivateKey.kem().raw(), kemCiphertext);
    SecretBytes classicalSecret = agree(recipientPrivateKey.raw(), ephemeral.get());
    const Bytes transcript = sealTranscript(
        kemCiphertext, ephemeralPublic, recipientPrivateKey.publicDer(), kid);

    SecretBytes key = deriveSealKey(pqSecret, classicalSecret, transcript);
    pqSecret.clear();
    classicalSecret.clear();

    std::optional<SecretBytes> opened = aeadOpen(key.bytes(), nonce, ciphertext);
    key.clear();
    if (!opened) {
        throw std::runtime_error("sealed payload does not authenticate");
    }
    return std::move(*opened);
}

}  // namespace bazarish::hybrid
