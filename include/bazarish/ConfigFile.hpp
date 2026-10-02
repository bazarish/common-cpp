// Bazarish project (c) 2026
#pragma once

#include <nlohmann/json.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace bazarish {

// What a listener may be told to bind: TCP's range without port 0, which means
// "any free port" and is never what an operator typed on purpose.
inline constexpr int kMinPort = 1;
inline constexpr int kMaxPort = 65535;

// A JSON document on disk, as a store reads one of its records. Throws when the
// file cannot be opened or does not parse: a record that will not read is not an
// empty record.
nlohmann::json readJsonFile(const std::filesystem::path& path);

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

// A daemon's settings, read out of its config document.
//
// Every value a daemon runs on lives here rather than in its command line: two
// places to say the same thing is two answers to the same question, and the
// operator finds out which one won by reading a unit file. A daemon takes the
// path to this document and nothing else.
//
// Paths are dotted: "portal.listen.port".
class ConfigView {
public:
    explicit ConfigView(nlohmann::json document);

    // The value at `path`, or `fallback` when the document does not have it.
    // Throws when it has it as something else (a string where a number belongs).
    std::string text(const std::string& path, const std::string& fallback = {}) const;
    std::int64_t number(const std::string& path, std::int64_t fallback) const;
    bool flag(const std::string& path, bool fallback) const;
    std::vector<std::string> list(const std::string& path) const;

    // Whether the document names this path at all, for a setting whose absence
    // means something (a face that is simply not served).
    bool has(const std::string& path) const;

    // A host and a port, which this fleet asks for at nearly every turn.
    struct Endpoint {
        std::string host;
        int port = 0;
    };
    std::optional<Endpoint> endpoint(const std::string& path) const;

    const nlohmann::json& document() const { return document_; }

private:
    const nlohmann::json* find(const std::string& path) const;

    nlohmann::json document_;
};

// Writes the value only when it differs from what the file already holds, so a
// save patches the settings that changed and leaves the rest of the file alone.
template <class T>
void setIfChanged(ConfigFile& file, std::vector<std::string> keys, const T& wanted,
    const T& current)
{
    if (!(wanted == current)) {
        file.set(std::move(keys), wanted);
    }
}

// Applies {"host", "port"} at `key` to a host and a port, leaving whichever of
// the two the body does not name, and doing nothing at all when it does not name
// `key`. Throws std::invalid_argument on an empty host or a port outside
// kMinPort..kMaxPort: one place where every settings endpoint checks an address.
void readEndpointInto(
    const nlohmann::json& body, const std::string& key, std::string& host, int& port);

// The patch itself, on text rather than a file: exposed for testing, and for a
// caller holding the document in memory.
std::string configWithValue(
    const std::string& text, const std::vector<std::string>& keys, const nlohmann::json& value);

}  // namespace bazarish
