// Bazarish project (c) 2026
#include "AccountKey.hpp"

#include <bazarish/Argon2.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/PrivateFile.hpp>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <system_error>

namespace bazarish::client::accountkey {

namespace {

namespace fs = std::filesystem;

constexpr char kMagic[4] = {'B', 'Z', 'K', '1'};
constexpr std::size_t kKeyBytes = bazarish::kAeadKeyBytes;
constexpr std::size_t kSaltBytes = 16;
constexpr std::size_t kNonceBytes = bazarish::kAeadNonceBytes;
constexpr std::size_t kTagBytes = bazarish::kAeadTagBytes;

constexpr std::uint32_t kMemoryKiB = 64 * 1024;
constexpr std::uint32_t kPasses = 3;
constexpr std::uint32_t kOpenMemoryKiB = 8 * 1024;
constexpr std::uint32_t kOpenPasses = 1;
constexpr std::uint32_t kLanes = 1;

constexpr std::size_t kSidecarBytes = sizeof kMagic + 2 * sizeof(std::uint32_t) + kSaltBytes
    + kNonceBytes + kKeyBytes + kTagBytes;

constexpr std::uint32_t kMaxMemoryKiB = 1024 * 1024;
constexpr std::uint32_t kMaxPasses = 16;

constexpr const char* kOpenSecret = "bazarish";

struct Sidecar {
    std::uint32_t memoryKiB = kMemoryKiB;
    std::uint32_t passes = kPasses;
    std::array<unsigned char, kSaltBytes> salt{};
    std::array<unsigned char, kNonceBytes> nonce{};
    std::array<unsigned char, kKeyBytes> sealed{};
    std::array<unsigned char, kTagBytes> tag{};
};

struct Cached {
    Bytes verifier;
    Bytes key;
};
std::mutex g_cacheMutex;
std::map<fs::path, Cached> g_cache;
// One per database, held from looking for its key to making it: two first opens make one key.
std::map<fs::path, std::weak_ptr<std::mutex>> g_pathLocks;

std::shared_ptr<std::mutex> pathLock(const fs::path& databaseFile)
{
    const std::lock_guard<std::mutex> lock(g_cacheMutex);
    std::erase_if(g_pathLocks, [](const auto& entry) { return entry.second.expired(); });
    std::weak_ptr<std::mutex>& held = g_pathLocks[databaseFile];
    std::shared_ptr<std::mutex> mutex = held.lock();
    if (!mutex) {
        mutex = std::make_shared<std::mutex>();
        held = mutex;
    }
    return mutex;
}

Bytes verifierOf(const std::string& passphrase)
{
    const std::string labelled = std::string("bazarish-account-key") + '\0' + passphrase;
    return sha256(Bytes(labelled.begin(), labelled.end()));
}

std::string secretOf(const std::string& passphrase)
{
    return passphrase.empty() ? std::string(kOpenSecret) : passphrase;
}

void fill(const ByteBuffer out)
{
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("account key: no randomness available");
    }
}

Bytes wrappingKey(const std::string& passphrase, const Sidecar& sidecar)
{
    const std::string secret = secretOf(passphrase);
    return argon2id(Bytes(secret.begin(), secret.end()),
        Bytes(sidecar.salt.begin(), sidecar.salt.end()), {sidecar.memoryKiB, sidecar.passes, kLanes},
        kKeyBytes);
}

void seal(const Bytes& wrapping, Sidecar& sidecar, const Bytes& key)
{
    const Bytes sealed
        = aeadSeal(wrapping, Bytes(sidecar.nonce.begin(), sidecar.nonce.end()), key);
    if (sealed.size() != kKeyBytes + kTagBytes) {
        throw std::runtime_error("account key: the key is not the size it should be");
    }
    const auto tagAt = sealed.begin() + static_cast<std::ptrdiff_t>(kKeyBytes);
    std::copy(sealed.begin(), tagAt, sidecar.sealed.begin());
    std::copy(tagAt, sealed.end(), sidecar.tag.begin());
}

bool unseal(const Bytes& wrapping, const Sidecar& sidecar, Bytes& key)
{
    Bytes sealed(sidecar.sealed.size() + sidecar.tag.size());
    const auto tagAt = std::copy(sidecar.sealed.begin(), sidecar.sealed.end(), sealed.begin());
    std::copy(sidecar.tag.begin(), sidecar.tag.end(), tagAt);
    std::optional<Bytes> opened
        = aeadOpen(wrapping, Bytes(sidecar.nonce.begin(), sidecar.nonce.end()), sealed);
    if (!opened.has_value()) {
        key.clear();
        return false;
    }
    key = std::move(*opened);
    return true;
}

void write(const fs::path& file, const Sidecar& sidecar)
{
    std::string out(kMagic, sizeof kMagic);
    for (const std::uint32_t value : {sidecar.memoryKiB, sidecar.passes}) {
        for (std::size_t i = 0; i < sizeof value; ++i) {
            out.push_back(static_cast<char>((value >> (8 * i)) & 0xFF));
        }
    }
    const auto append = [&out](const auto& part) {
        out.append(reinterpret_cast<const char*>(part.data()), part.size());
    };
    append(sidecar.salt);
    append(sidecar.nonce);
    append(sidecar.sealed);
    append(sidecar.tag);
    writePrivateFile(file, out);
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

Sidecar freshSidecar(const std::string& passphrase)
{
    Sidecar sidecar;
    if (passphrase.empty()) {
        sidecar.memoryKiB = kOpenMemoryKiB;
        sidecar.passes = kOpenPasses;
    }
    fill(sidecar.salt);
    fill(sidecar.nonce);
    return sidecar;
}

Bytes create(const fs::path& file, const std::string& passphrase)
{
    Sidecar sidecar = freshSidecar(passphrase);
    Bytes key(kKeyBytes);
    fill(key);
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
    const std::shared_ptr<std::mutex> forThisFile = pathLock(databaseFile);
    const std::lock_guard<std::mutex> making(*forThisFile);
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
    if (!fs::exists(sidecar) && fs::exists(databaseFile)) {
        throw std::runtime_error("account key: " + sidecarFor(databaseFile).string()
            + " is missing - the account cannot be opened without it");
    }
    Bytes key = fs::exists(sidecar) ? open(sidecar, passphrase) : create(sidecar, passphrase);
    const std::lock_guard<std::mutex> lock(g_cacheMutex);
    g_cache[databaseFile] = Cached{verifier, key};
    return key;
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
