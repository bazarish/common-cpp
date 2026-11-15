// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <filesystem>
#include <stdexcept>
#include <string>

namespace bazarish::client {

namespace accountkey {

// An account without a passphrase is sealed under this one, so no account may choose it.
inline constexpr const char* kOpenSecret = "bazarish";

class ReservedPassphrase : public std::invalid_argument {
public:
    ReservedPassphrase();
};

bool isReservedPassphrase(const std::string& passphrase);

std::filesystem::path sidecarFor(const std::filesystem::path& databaseFile);

Bytes keyFor(const std::filesystem::path& databaseFile, const std::string& passphrase);

// Re-encrypts under a fresh key; nothing else may have the database open.
void rekey(const std::filesystem::path& databaseFile, const std::string& oldPassphrase,
    const std::string& newPassphrase);

void removeKeyFiles(const std::filesystem::path& databaseFile);

// Argon2id at the at-rest cost and AES-256-GCM over a header that names the cost.
Bytes sealBackup(const Bytes& plain, const std::string& passphrase);
Bytes openBackup(const Bytes& sealed, const std::string& passphrase);

void forget(const std::filesystem::path& databaseFile);

}  // namespace accountkey

}  // namespace bazarish::client
