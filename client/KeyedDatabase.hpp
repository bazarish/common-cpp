// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <filesystem>

struct sqlite3;

namespace bazarish::client {

// Null when the file cannot be opened or the key does not read it.
sqlite3* openKeyed(const std::filesystem::path& file, const Bytes& key);

// A whole copy under the same key while other connections keep writing to the source.
void copyKeyedDatabase(
    const std::filesystem::path& from, const std::filesystem::path& to, const Bytes& key);

}  // namespace bazarish::client
