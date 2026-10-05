// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace bazarish {

// The whole file as text. Throws when it cannot be opened.
std::string readFileText(const std::filesystem::path& path);

// Writes through a temporary beside the target and renames: a reader never sees a
// half-written record, and a machine that stops mid-write leaves the old one.
// Throws on any failure.
void writeFileAtomic(const std::filesystem::path& path, std::string_view bytes);
void writeFileAtomic(const std::filesystem::path& path, const Bytes& bytes);

// The same, for key material: the permissions are set on the temporary before it
// is put in place, so the target is never briefly there for everyone to read.
//
// Throws on any failure. A key file that was not written, or was written for
// everyone, is not something to carry on from.
void writePrivateFile(const std::filesystem::path& path, const std::string& text);

}  // namespace bazarish
