// Bazarish project (c) 2026
#include "AccountKey.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <stdexcept>
#include <system_error>

namespace bazarish::client::accountkey {

namespace {

namespace fs = std::filesystem;

// The sidecar's own format. Everything but the sealed key is public: it has to
// be, since it is what says how to derive the wrapping key in the first place.
constexpr char kMagic[4] = {'B', 'Z', 'K', '1'};
constexpr std::size_t kKeyBytes = 32;      // AES-256 for the database
constexpr std::size_t kSaltBytes = 16;     // Argon2id salt
constexpr std::size_t kNonceBytes = 12;    // AES-GCM nonce
constexpr std::size_t kTagBytes = 16;      // AES-GCM tag

// Argon2id cost for an account the user gave a passphrase: memory-hard, so a
// stolen sidecar is expensive to attack with a GPU rather than merely slow.
// Roughly a third of a second on a desktop; the numbers are written into the
// sidecar, so they can be raised later without stranding existing accounts.
constexpr std::uint32_t kMemoryKiB = 64 * 1024;
constexpr std::uint32_t kPasses = 3;
// An account with no passphrase has nothing to stretch - the wrapping "secret" is
// a constant in this file - so it pays the smallest cost the format allows
// instead of a third of a second for nothing.
constexpr std::uint32_t kOpenMemoryKiB = 8 * 1024;
constexpr std::uint32_t kOpenPasses = 1;
// Argon2id in OpenSSL runs multi-lane only with a thread pool on the library
// context; one lane needs no such setup.
constexpr std::uint32_t kLanes = 1;

// The whole record: magic, the two cost values, and the fixed fields. The size
// is exact, so a file of any other length is not this format whatever its first
// bytes say.
constexpr std::size_t kSidecarBytes = sizeof kMagic + 2 * sizeof(std::uint32_t) + kSaltBytes
    + kNonceBytes + kKeyBytes + kTagBytes;

// The most the file is allowed to ask the derivation for. The cost lives in the
// sidecar so it can be raised later, but the sidecar is a file on disk: what it
// asks for has to be something this machine can actually spend, or opening an
// account is however much memory the file names. Raising the cost above these
// means raising these first.
constexpr std::uint32_t kMaxMemoryKiB = 1024 * 1024;  // 1 GiB
constexpr std::uint32_t kMaxPasses = 16;

// What an account with no passphrase is wrapped under. It is not a secret - it is
// right here - so it protects nothing; it keeps one code path and stops the file
// from being readable by accident.
//
// That an account may be made without a passphrase at all is a decision, not an
// omission: the cost of a forgotten one is an account nobody can open ever again,
// and for most people that is the likelier loss. Anyone who wants the file itself
// protected sets a passphrase, and then the key is derived from it. Do not
// "fix" this into a requirement without deciding that trade afresh.
constexpr const char* kOpenSecret = "bazarish";

struct Sidecar {
    std::uint32_t memoryKiB = kMemoryKiB;
    std::uint32_t passes = kPasses;
    std::array<unsigned char, kSaltBytes> salt{};
    std::array<unsigned char, kNonceBytes> nonce{};
    std::array<unsigned char, kKeyBytes> sealed{};
    std::array<unsigned char, kTagBytes> tag{};
};

// The unwrapped keys of the accounts opened in this process: an account is opened
// by more than one connection (its state and its transcript), and the derivation
// is the whole cost of opening it. The entry remembers which passphrase produced
// it, so the cache can never hand the key to a caller that does not have it.
struct Cached {
    Bytes verifier;
    Bytes key;
};
std::mutex g_cacheMutex;
std::map<fs::path, Cached> g_cache;

// What the cache compares a passphrase against. Never written anywhere.
Bytes verifierOf(const std::string& passphrase)
{
    Bytes digest(EVP_MAX_MD_SIZE);
    unsigned int size = 0;
    const std::string labelled = "bazarish-account-key\0" + passphrase;
    if (EVP_Digest(labelled.data(), labelled.size(), digest.data(), &size, EVP_sha256(), nullptr)
        != 1) {
        throw std::runtime_error("account key: could not hash the passphrase");
    }
    digest.resize(size);
    return digest;
}

std::string secretOf(const std::string& passphrase)
{
    return passphrase.empty() ? std::string(kOpenSecret) : passphrase;
}

void fill(unsigned char* const out, const std::size_t size)
{
    if (RAND_bytes(out, static_cast<int>(size)) != 1) {
        throw std::runtime_error("account key: no randomness available");
    }
}

// Argon2id over the passphrase, giving the key the sidecar is sealed with.
Bytes wrappingKey(const std::string& passphrase, const Sidecar& sidecar)
{
    EVP_KDF* const kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (kdf == nullptr) {
        throw std::runtime_error("account key: this OpenSSL has no Argon2id");
    }
    EVP_KDF_CTX* const ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == nullptr) {
        throw std::runtime_error("account key: could not start the derivation");
    }
    const std::string secret = secretOf(passphrase);
    std::uint32_t memory = sidecar.memoryKiB;
    std::uint32_t passes = sidecar.passes;
    std::uint32_t lanes = kLanes;
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            "pass", const_cast<char*>(secret.data()), secret.size()),
        OSSL_PARAM_construct_octet_string(
            "salt", const_cast<unsigned char*>(sidecar.salt.data()), sidecar.salt.size()),
        OSSL_PARAM_construct_uint("memcost", &memory),
        OSSL_PARAM_construct_uint("iter", &passes),
        OSSL_PARAM_construct_uint("lanes", &lanes),
        OSSL_PARAM_construct_uint("threads", &lanes),
        OSSL_PARAM_construct_end(),
    };
    Bytes derived(kKeyBytes);
    const int ok = EVP_KDF_derive(ctx, derived.data(), derived.size(), params);
    EVP_KDF_CTX_free(ctx);
    if (ok <= 0) {
        throw std::runtime_error("account key: the derivation failed");
    }
    return derived;
}

// AES-256-GCM both ways. The sealed value is exactly the database key, so a
// wrong passphrase fails on the tag rather than handing back rubbish.
void seal(const Bytes& wrapping, Sidecar& sidecar, const Bytes& key)
{
    EVP_CIPHER_CTX* const ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("account key: no cipher context");
    }
    int length = 0;
    const bool ok
        = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, wrapping.data(), sidecar.nonce.data())
            == 1
        && EVP_EncryptUpdate(ctx, sidecar.sealed.data(), &length, key.data(),
               static_cast<int>(key.size()))
            == 1
        && EVP_EncryptFinal_ex(ctx, sidecar.sealed.data() + length, &length) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(sidecar.tag.size()),
               sidecar.tag.data())
            == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        throw std::runtime_error("account key: could not seal the key");
    }
}

bool unseal(const Bytes& wrapping, const Sidecar& sidecar, Bytes& key)
{
    EVP_CIPHER_CTX* const ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("account key: no cipher context");
    }
    key.assign(kKeyBytes, 0);
    int length = 0;
    bool ok
        = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, wrapping.data(), sidecar.nonce.data())
            == 1
        && EVP_DecryptUpdate(ctx, key.data(), &length, sidecar.sealed.data(), kKeyBytes) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(sidecar.tag.size()),
               const_cast<unsigned char*>(sidecar.tag.data()))
            == 1;
    if (ok) {
        // A failure here is the tag check: this passphrase is not the one.
        ok = EVP_DecryptFinal_ex(ctx, key.data() + length, &length) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        key.clear();
    }
    return ok;
}

void write(const fs::path& file, const Sidecar& sidecar)
{
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    out.write(kMagic, sizeof kMagic);
    for (const std::uint32_t value : {sidecar.memoryKiB, sidecar.passes}) {
        std::array<unsigned char, 4> bytes{};
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            bytes[i] = static_cast<unsigned char>((value >> (8 * i)) & 0xFF);
        }
        out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
    out.write(reinterpret_cast<const char*>(sidecar.salt.data()), sidecar.salt.size());
    out.write(reinterpret_cast<const char*>(sidecar.nonce.data()), sidecar.nonce.size());
    out.write(reinterpret_cast<const char*>(sidecar.sealed.data()), sidecar.sealed.size());
    out.write(reinterpret_cast<const char*>(sidecar.tag.data()), sidecar.tag.size());
    if (!out) {
        throw std::runtime_error("account key: could not write " + file.string());
    }
}

Sidecar read(const fs::path& file)
{
    std::error_code failed;
    const std::uintmax_t size = fs::file_size(file, failed);
    if (failed) {
        throw std::runtime_error(
            "account key: could not read " + file.string() + ": " + failed.message());
    }
    if (size != kSidecarBytes) {
        throw std::runtime_error("account key: " + file.string() + " is not a key file: "
            + std::to_string(size) + " bytes, and the record is " + std::to_string(kSidecarBytes));
    }
    std::ifstream in(file, std::ios::binary);
    std::array<char, sizeof kMagic> magic{};
    in.read(magic.data(), magic.size());
    if (!in || std::memcmp(magic.data(), kMagic, sizeof kMagic) != 0) {
        throw std::runtime_error("account key: " + file.string() + " is not a key file");
    }
    Sidecar sidecar;
    for (std::uint32_t* const value : {&sidecar.memoryKiB, &sidecar.passes}) {
        std::array<unsigned char, 4> bytes{};
        in.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
        *value = 0;
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            *value |= static_cast<std::uint32_t>(bytes[i]) << (8 * i);
        }
    }
    in.read(reinterpret_cast<char*>(sidecar.salt.data()), sidecar.salt.size());
    in.read(reinterpret_cast<char*>(sidecar.nonce.data()), sidecar.nonce.size());
    in.read(reinterpret_cast<char*>(sidecar.sealed.data()), sidecar.sealed.size());
    in.read(reinterpret_cast<char*>(sidecar.tag.data()), sidecar.tag.size());
    if (!in) {
        throw std::runtime_error("account key: " + file.string() + " could not be read in full");
    }
    if (sidecar.memoryKiB > kMaxMemoryKiB || sidecar.passes > kMaxPasses) {
        throw std::runtime_error("account key: " + file.string() + " asks for a derivation cost "
            + "this build refuses: " + std::to_string(sidecar.memoryKiB) + " KiB over "
            + std::to_string(sidecar.passes) + " passes");
    }
    return sidecar;
}

// New salt and nonce, and the cost this passphrase gets: an empty one has nothing
// to slow down, so it takes the open profile.
Sidecar freshSidecar(const std::string& passphrase)
{
    Sidecar sidecar;
    if (passphrase.empty()) {
        sidecar.memoryKiB = kOpenMemoryKiB;
        sidecar.passes = kOpenPasses;
    }
    fill(sidecar.salt.data(), sidecar.salt.size());
    fill(sidecar.nonce.data(), sidecar.nonce.size());
    return sidecar;
}

// Creates the sidecar for an account that has none: a fresh database key, sealed.
Bytes create(const fs::path& file, const std::string& passphrase)
{
    Sidecar sidecar = freshSidecar(passphrase);
    Bytes key(kKeyBytes);
    fill(key.data(), key.size());
    seal(wrappingKey(passphrase, sidecar), sidecar, key);
    write(file, sidecar);
    return key;
}

Bytes open(const fs::path& file, const std::string& passphrase)
{
    const Sidecar sidecar = read(file);
    Bytes key;
    if (!unseal(wrappingKey(passphrase, sidecar), sidecar, key)) {
        throw std::runtime_error("account key: wrong passphrase");
    }
    return key;
}

}  // namespace

fs::path sidecarFor(const fs::path& databaseFile)
{
    fs::path sidecar = databaseFile;
    sidecar.replace_extension(".key");
    return sidecar;
}

Bytes keyFor(const fs::path& databaseFile, const std::string& passphrase)
{
    const Bytes verifier = verifierOf(passphrase);
    {
        const std::lock_guard<std::mutex> lock(g_cacheMutex);
        const auto found = g_cache.find(databaseFile);
        if (found != g_cache.end() && found->second.verifier.size() == verifier.size()
            && CRYPTO_memcmp(found->second.verifier.data(), verifier.data(), verifier.size())
                == 0) {
            return found->second.key;
        }
    }
    const fs::path sidecar = sidecarFor(databaseFile);
    // A database with no key beside it is not a new account: minting one here
    // would hand back a key the database was never written with, and the account
    // would be lost behind an "unreadable database" that no passphrase can fix.
    if (!fs::exists(sidecar) && fs::exists(databaseFile)) {
        throw std::runtime_error("account key: " + sidecarFor(databaseFile).string()
            + " is missing - the account cannot be opened without it");
    }
    Bytes key = fs::exists(sidecar) ? open(sidecar, passphrase) : create(sidecar, passphrase);
    const std::lock_guard<std::mutex> lock(g_cacheMutex);
    g_cache[databaseFile] = Cached{verifier, key};
    return key;
}

bool unlocks(const fs::path& databaseFile, const std::string& passphrase)
{
    try {
        (void)keyFor(databaseFile, passphrase);
        return true;
    } catch (const std::exception&) {
        return false;  // the caller asked precisely so it would not have to catch
    }
}

void rewrap(const fs::path& databaseFile, const std::string& passphrase)
{
    Bytes key;
    {
        const std::lock_guard<std::mutex> lock(g_cacheMutex);
        const auto found = g_cache.find(databaseFile);
        if (found == g_cache.end()) {
            throw std::runtime_error("account key: the account is not open");
        }
        key = found->second.key;
    }
    Sidecar sidecar = freshSidecar(passphrase);
    seal(wrappingKey(passphrase, sidecar), sidecar, key);
    write(sidecarFor(databaseFile), sidecar);
}

void forget(const fs::path& databaseFile)
{
    const std::lock_guard<std::mutex> lock(g_cacheMutex);
    g_cache.erase(databaseFile);
}

}  // namespace bazarish::client::accountkey
