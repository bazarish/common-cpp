// Bazarish project (c) 2026
#include "bazarish/Hybrid.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace {

using bazarish::Bytes;
using bazarish::Key;

constexpr const char* kSignContext = "bazarish-composite-sig-v1";
constexpr const char* kSealContext = "bazarish-composite-seal-v1";
constexpr const char* kKdfName = "HKDF";
constexpr const char* kKdfDigest = "SHA256";
constexpr std::size_t kX25519SharedSecretBytes = 32;

struct PkeyDeleter {
    void operator()(EVP_PKEY* key) const
    {
        EVP_PKEY_free(key);
    }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

struct PkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ctx) const
    {
        EVP_PKEY_CTX_free(ctx);
    }
};
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter>;

struct KdfCtxDeleter {
    void operator()(EVP_KDF_CTX* ctx) const
    {
        EVP_KDF_CTX_free(ctx);
    }
};
using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter>;

void append(Bytes& target, const Bytes& tail)
{
    target.insert(target.end(), tail.begin(), tail.end());
}

void cleanse(Bytes& secret)
{
    if (!secret.empty()) {
        OPENSSL_cleanse(secret.data(), secret.size());
    }
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
    const nlohmann::json parsed = nlohmann::json::from_cbor(
        frame, true, true, nlohmann::json::cbor_tag_handler_t::error);
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

// Both halves sign the same message, and it names both public keys: swapping
// either half invalidates the other half's signature.
Bytes signedMessage(
    const Bytes& classicalPublicDer, const Bytes& pqPublicDer, const Bytes& body)
{
    Bytes keys = classicalPublicDer;
    append(keys, pqPublicDer);
    Bytes message = contextBytes(kSignContext);
    append(message, bazarish::sha256(keys));
    append(message, body);
    return message;
}

Bytes sealTranscript(const Bytes& kemCiphertext, const Bytes& ephemeralPublic,
    const Bytes& recipientPublicDer)
{
    Bytes transcript = kemCiphertext;
    append(transcript, ephemeralPublic);
    append(transcript, recipientPublicDer);
    return transcript;
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

Bytes agree(EVP_PKEY* const ours, EVP_PKEY* const theirs)
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
    Bytes secret(size);
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
    Bytes sharedSecret;
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
    Encapsulation result{Bytes(ciphertextSize), Bytes(secretSize)};
    if (EVP_PKEY_encapsulate(ctx.get(), result.ciphertext.data(), &ciphertextSize,
            result.sharedSecret.data(), &secretSize)
        != 1) {
        throw std::runtime_error("ML-KEM encapsulate failed");
    }
    result.ciphertext.resize(ciphertextSize);
    result.sharedSecret.resize(secretSize);
    return result;
}

Bytes decapsulate(EVP_PKEY* const recipientKem, const Bytes& ciphertext)
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
    Bytes secret(secretSize);
    if (EVP_PKEY_decapsulate(
            ctx.get(), secret.data(), &secretSize, ciphertext.data(), ciphertext.size())
        != 1) {
        throw std::runtime_error("ML-KEM decapsulate failed");
    }
    secret.resize(secretSize);
    return secret;
}

Bytes deriveSealKey(const Bytes& pqSecret, const Bytes& classicalSecret, const Bytes& transcript)
{
    EVP_KDF* const kdf = EVP_KDF_fetch(nullptr, kKdfName, nullptr);
    if (kdf == nullptr) {
        throw std::runtime_error("HKDF unavailable");
    }
    const KdfCtxPtr ctx(EVP_KDF_CTX_new(kdf));
    EVP_KDF_free(kdf);
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_KDF_CTX_new failed");
    }
    Bytes material = pqSecret;
    append(material, classicalSecret);
    Bytes context = contextBytes(kSealContext);
    Bytes transcriptCopy = transcript;
    Bytes key(bazarish::kAeadKeyBytes);
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(kKdfDigest), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, material.data(), material.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, transcriptCopy.data(), transcriptCopy.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, context.data(), context.size()),
        OSSL_PARAM_construct_end(),
    };
    const int ok = EVP_KDF_derive(ctx.get(), key.data(), key.size(), params);
    cleanse(material);
    if (ok != 1) {
        throw std::runtime_error("HKDF derive failed");
    }
    return key;
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
        nlohmann::json::parse(bodyBytes.begin(), bodyBytes.end()),
        hybridFingerprint(classicalPublicDer, pqPublicDer),
        classicalPublicDer,
        pqPublicDer,
    };
}

Bytes seal(const Bytes& plaintext, const Key& recipientPublicKey)
{
    if (!recipientPublicKey.hasKem()) {
        throw std::logic_error("sealing requires a hybrid (ML-KEM) recipient key");
    }
    if (!recipientPublicKey.isA(kClassicalSealingAlgorithm)) {
        throw std::logic_error("sealing requires an X25519 classical half");
    }

    Encapsulation encapsulated = encapsulate(recipientPublicKey.kem().raw());
    const PkeyPtr ephemeral = generateEphemeral();
    const Bytes ephemeralPublic = rawPublicKey(ephemeral.get());
    Bytes classicalSecret = agree(ephemeral.get(), recipientPublicKey.raw());
    const Bytes transcript = sealTranscript(
        encapsulated.ciphertext, ephemeralPublic, recipientPublicKey.publicDer());

    Bytes key = deriveSealKey(encapsulated.sharedSecret, classicalSecret, transcript);
    cleanse(encapsulated.sharedSecret);
    cleanse(classicalSecret);

    const Bytes nonce = randomBytes(kAeadNonceBytes);
    const Bytes ciphertext = aeadSeal(key, nonce, plaintext);
    cleanse(key);

    const nlohmann::json frame = {
        {"v", kFrameVersion},
        {"kem", nlohmann::json::binary(encapsulated.ciphertext)},
        {"eph", nlohmann::json::binary(ephemeralPublic)},
        {"n", nlohmann::json::binary(nonce)},
        {"ct", nlohmann::json::binary(ciphertext)},
    };
    return nlohmann::json::to_cbor(frame);
}

Bytes unseal(const Bytes& frame, const Key& recipientPrivateKey)
{
    if (!recipientPrivateKey.hasPrivate()) {
        throw std::logic_error("unsealing requires a private key");
    }
    if (!recipientPrivateKey.hasKem()) {
        throw std::logic_error("unsealing requires a hybrid (ML-KEM) key");
    }
    if (!recipientPrivateKey.isA(kClassicalSealingAlgorithm)) {
        throw std::logic_error("unsealing requires an X25519 classical half");
    }

    const nlohmann::json parsed = parseFrame(frame);
    requireVersion(parsed);
    const Bytes kemCiphertext = bytesOf(parsed.at("kem").get_binary());
    const Bytes ephemeralPublic = bytesOf(parsed.at("eph").get_binary());
    const Bytes nonce = bytesOf(parsed.at("n").get_binary());
    const Bytes ciphertext = bytesOf(parsed.at("ct").get_binary());

    const PkeyPtr ephemeral = publicKeyFromRaw(ephemeralPublic);
    Bytes pqSecret = decapsulate(recipientPrivateKey.kem().raw(), kemCiphertext);
    Bytes classicalSecret = agree(recipientPrivateKey.raw(), ephemeral.get());
    const Bytes transcript = sealTranscript(
        kemCiphertext, ephemeralPublic, recipientPrivateKey.publicDer());

    Bytes key = deriveSealKey(pqSecret, classicalSecret, transcript);
    cleanse(pqSecret);
    cleanse(classicalSecret);

    const std::optional<Bytes> opened = aeadOpen(key, nonce, ciphertext);
    cleanse(key);
    if (!opened) {
        throw std::runtime_error("sealed payload does not authenticate");
    }
    return *opened;
}

}  // namespace bazarish::hybrid
