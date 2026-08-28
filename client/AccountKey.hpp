// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <filesystem>
#include <string>

namespace bazarish::client {

// The key an account database is encrypted with, and the small record that keeps
// it: "<account>.key" beside "<account>.db".
//
// The database itself is opened with a random 32-byte key and no key derivation
// at all, so opening it costs nothing. That key is what the sidecar holds, sealed
// under the user's passphrase with Argon2id - the one expensive step, paid once
// when the account is unlocked. Changing the passphrase rewrites those hundred
// bytes instead of re-encrypting every page of the database.
namespace accountkey {

// The sidecar that belongs to an account database.
std::filesystem::path sidecarFor(const std::filesystem::path& databaseFile);

// The database key for this account, creating the sidecar (and a fresh random
// key) when there is none. Throws when the passphrase does not open an existing
// sidecar - a wrong passphrase must never read as a new account. The unwrapped
// key is remembered for the life of the process, so the second connection to the
// same account does not pay the derivation again.
Bytes keyFor(const std::filesystem::path& databaseFile, const std::string& passphrase);

// Whether this passphrase opens the account, without throwing.
bool unlocks(const std::filesystem::path& databaseFile, const std::string& passphrase);

// Re-seals the same database key under a new passphrase. The database is not
// touched.
void rewrap(const std::filesystem::path& databaseFile, const std::string& passphrase);

// Drops the remembered key (an account being closed or removed).
void forget(const std::filesystem::path& databaseFile);

}  // namespace accountkey

}  // namespace bazarish::client
