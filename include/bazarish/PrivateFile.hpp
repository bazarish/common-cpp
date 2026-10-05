// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace bazarish {

std::string readFileText(const std::filesystem::path& path);

void writeFileAtomic(const std::filesystem::path& path, std::string_view bytes);
void writeFileAtomic(const std::filesystem::path& path, const Bytes& bytes);

void writePrivateFile(const std::filesystem::path& path, const std::string& text);

}  // namespace bazarish
