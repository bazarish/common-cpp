// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>

namespace bazarish::cms {

// CMS EnvelopedData with a password recipient (RFC 3211 PWRI), its content in a file of its own.
using PlainReadFn = std::function<std::size_t(ByteBuffer buffer)>;
Bytes sealWithPasswordDetached(const PlainReadFn& read, const std::filesystem::path& contentPath,
    const std::string& password);

using PlainWriteFn = std::function<void(ByteView data)>;
void unsealWithPasswordDetached(const Bytes& header, const std::filesystem::path& contentPath,
    const std::string& password, const PlainWriteFn& write);

}  // namespace bazarish::cms
