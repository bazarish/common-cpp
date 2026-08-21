// Bazarish project (c) 2026
#pragma once

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>
#include <vector>

namespace bazarish {

// A daemon's config file, which a control plane may change one value at a time.
//
// The file belongs to the operator: their key order, their indentation and their
// comments are theirs, and a daemon that rewrites a setting must give the rest of
// the file back byte for byte. So a write is a patch of one value's text, not a
// re-serialisation of a parsed document - the way an editor would do it, not the
// way a parser would.
//
// Comments (// and /* */) are allowed and survive a write.
class ConfigFile {
public:
    explicit ConfigFile(std::filesystem::path path);

    const std::filesystem::path& path() const { return path_; }

    // The file as a document. Throws when it cannot be read or parsed.
    nlohmann::json read() const;

    // Replaces the value at `keys` (["registration", "requireApproval"]) with
    // `value`, creating the key - and the objects above it - when missing.
    // Everything else in the file is left exactly as it was. Throws when the file
    // cannot be read or written, or when a key on the path exists but is not an
    // object.
    void set(const std::vector<std::string>& keys, const nlohmann::json& value);

private:
    std::filesystem::path path_;
};

// The patch itself, on text rather than a file: exposed for testing, and for a
// caller holding the document in memory.
std::string configWithValue(
    const std::string& text, const std::vector<std::string>& keys, const nlohmann::json& value);

}  // namespace bazarish
