// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace bazarish {

std::string readFileText(const std::filesystem::path& path);
Bytes readFileBytes(const std::filesystem::path& path);

void writeFileAtomic(const std::filesystem::path& path, std::string_view bytes);
void writeFileAtomic(const std::filesystem::path& path, const Bytes& bytes);
// The new file has these permissions from its first byte on.
void writeFileAtomic(
    const std::filesystem::path& path, std::string_view bytes, std::filesystem::perms perms);

void writePrivateFile(const std::filesystem::path& path, const std::string& text);

void syncDirectory(const std::filesystem::path& directory);

}  // namespace bazarish
