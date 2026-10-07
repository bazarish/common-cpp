// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <filesystem>
#include <string>

namespace bazarish::cms {

// CMS EnvelopedData with a password recipient (RFC 3211 PWRI).
Bytes sealWithPassword(const Bytes& plaintext, const std::string& password);
Bytes unsealWithPassword(const Bytes& der, const std::string& password);

// The file forms stream, so a payload never has to fit in memory.
void sealWithPasswordToFile(const std::filesystem::path& inPath,
    const std::filesystem::path& outPath, const std::string& password);

void unsealWithPasswordToFile(const std::filesystem::path& derPath,
    const std::filesystem::path& outPath, const std::string& password);

}  // namespace bazarish::cms
