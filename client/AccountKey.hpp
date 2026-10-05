// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <filesystem>
#include <string>

namespace bazarish::client {

namespace accountkey {

std::filesystem::path sidecarFor(const std::filesystem::path& databaseFile);

Bytes keyFor(const std::filesystem::path& databaseFile, const std::string& passphrase);

bool unlocks(const std::filesystem::path& databaseFile, const std::string& passphrase);

void rewrap(const std::filesystem::path& databaseFile, const std::string& passphrase);

void forget(const std::filesystem::path& databaseFile);

}  // namespace accountkey

}  // namespace bazarish::client
