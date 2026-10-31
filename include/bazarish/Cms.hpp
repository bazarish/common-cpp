// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>

namespace bazarish::cms {

// CMS EnvelopedData with a password recipient (RFC 3211 PWRI).
Bytes sealWithPassword(const Bytes& plaintext, const std::string& password);
Bytes unsealWithPassword(const Bytes& der, const std::string& password);

// The decoder reads an attached envelope whole into memory, so the file forms are detached.
using PlainReadFn = std::function<std::size_t(void* buffer, std::size_t size)>;
Bytes sealWithPasswordDetached(const PlainReadFn& read, const std::filesystem::path& contentPath,
    const std::string& password);

using PlainWriteFn = std::function<void(const void* data, std::size_t size)>;
void unsealWithPasswordDetached(const Bytes& header, const std::filesystem::path& contentPath,
    const std::string& password, const PlainWriteFn& write);

}  // namespace bazarish::cms
