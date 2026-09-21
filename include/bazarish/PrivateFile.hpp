// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <string>

namespace bazarish {

// The whole file as text. Throws when it cannot be opened.
std::string readFileText(const std::filesystem::path& path);

// Writes key material: atomically, and readable by its owner alone.
//
// Both halves matter and neither is optional. A truncate-then-write loses the
// key it is replacing when the machine stops mid-write, and a key that is gone
// cannot be regenerated - what was sealed to it stays sealed. Permissions are
// set on the temporary file before it is put in place, so the target is never
// briefly there for everyone to read.
//
// Throws on any failure. A key file that was not written, or was written for
// everyone, is not something to carry on from.
void writePrivateFile(const std::filesystem::path& path, const std::string& text);

}  // namespace bazarish
