// Bazarish project (c) 2026
#pragma once

#include "TestUtil.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/SecretBytes.hpp>

#include <openssl/evp.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

namespace testutil {

// SQLCipher 4 defaults: 4096-byte pages, each ending in a 16-byte IV and a 64-byte HMAC.
inline constexpr std::size_t kPageBytes = 4096;
inline constexpr std::size_t kReserveBytes = 80;
inline constexpr std::size_t kSaltBytes = 16;
// SQLite's WAL format: a 32-byte file header, then a 24-byte header before each page.
inline constexpr std::size_t kWalHeaderBytes = 32;
inline constexpr std::size_t kFrameHeaderBytes = 24;

inline bazarish::Bytes decryptedPage(
    const bazarish::Bytes& key, const unsigned char* const page, const bool first)
{
    const std::size_t from = first ? kSaltBytes : 0;
    const std::size_t size = kPageBytes - kReserveBytes - from;
    const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    bazarish::Bytes plain(size);
    int written = 0;
    CHECK(ctx != nullptr);
    CHECK(EVP_DecryptInit_ex(
              ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), page + kPageBytes - kReserveBytes)
        == 1);
    CHECK(EVP_CIPHER_CTX_set_padding(ctx.get(), 0) == 1);
    CHECK(EVP_DecryptUpdate(ctx.get(), plain.data(), &written, page + from, static_cast<int>(size))
        == 1);
    return plain;
}

inline bool pageHolds(const bazarish::Bytes& key, const unsigned char* const page,
    const bool first, const std::string& needle)
{
    const bazarish::Bytes plain = decryptedPage(key, page, first);
    return std::string(plain.begin(), plain.end()).find(needle) != std::string::npos;
}

// Reads every page the files hold, live or freed, current or superseded.
inline bool filesHold(const std::filesystem::path& database, const bazarish::SecretBytes& secret,
    const std::string& needle)
{
    const bazarish::Bytes& key = secret.bytes();
    const bazarish::Bytes pages = bazarish::readFileBytes(database);
    for (std::size_t at = 0; at + kPageBytes <= pages.size(); at += kPageBytes) {
        if (pageHolds(key, pages.data() + at, at == 0, needle)) {
            return true;
        }
    }
    std::filesystem::path wal = database;
    wal += "-wal";
    if (!std::filesystem::exists(wal)) {
        return false;
    }
    const bazarish::Bytes log = bazarish::readFileBytes(wal);
    for (std::size_t at = kWalHeaderBytes; at + kFrameHeaderBytes + kPageBytes <= log.size();
         at += kFrameHeaderBytes + kPageBytes) {
        const std::uint32_t pageNumber = (static_cast<std::uint32_t>(log[at]) << 24)
            | (static_cast<std::uint32_t>(log[at + 1]) << 16)
            | (static_cast<std::uint32_t>(log[at + 2]) << 8) | log[at + 3];
        if (pageHolds(key, log.data() + at + kFrameHeaderBytes, pageNumber == 1, needle)) {
            return true;
        }
    }
    return false;
}

}  // namespace testutil
