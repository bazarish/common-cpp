// Bazarish project (c) 2026
#include "bazarish/ConfigFile.hpp"

#include <cctype>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace bazarish {

namespace {

namespace fs = std::filesystem;

// How far in a nested object is indented from its parent when this code has to
// write a key the file did not have.
constexpr std::size_t kIndentWidth = 2;

std::string readWhole(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot read config " + path.string());
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

// The file is replaced only once it is whole: a crash mid-write must not leave a
// daemon without a config.
void writeWhole(const fs::path& path, const std::string& text)
{
    const fs::path temporary = path.string() + ".tmp";
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("cannot write " + temporary.string());
        }
        out << text;
        if (!out) {
            throw std::runtime_error("cannot write " + temporary.string());
        }
    }
    fs::rename(temporary, path);
}

// Everything between tokens: whitespace and the comments the operator wrote.
std::size_t skipGaps(const std::string& text, std::size_t at)
{
    while (at < text.size()) {
        if (std::isspace(static_cast<unsigned char>(text[at])) != 0) {
            ++at;
        } else if (text.compare(at, 2, "//") == 0) {
            at = text.find('\n', at);
            if (at == std::string::npos) {
                return text.size();
            }
        } else if (text.compare(at, 2, "/*") == 0) {
            const std::size_t end = text.find("*/", at + 2);
            if (end == std::string::npos) {
                return text.size();
            }
            at = end + 2;
        } else {
            return at;
        }
    }
    return at;
}

// The index just past a string token that starts at `at` (which must be its
// opening quote), escapes included.
std::size_t endOfString(const std::string& text, std::size_t at)
{
    for (++at; at < text.size(); ++at) {
        if (text[at] == '\\') {
            ++at;
            continue;
        }
        if (text[at] == '"') {
            return at + 1;
        }
    }
    throw std::runtime_error("config ends inside a string");
}

// The index just past the value that starts at `at`, whatever kind it is.
std::size_t endOfValue(const std::string& text, std::size_t at)
{
    at = skipGaps(text, at);
    if (at >= text.size()) {
        throw std::runtime_error("config ends where a value was expected");
    }
    if (text[at] == '"') {
        return endOfString(text, at);
    }
    if (text[at] == '{' || text[at] == '[') {
        const char open = text[at];
        const char close = open == '{' ? '}' : ']';
        int depth = 0;
        for (; at < text.size(); ++at) {
            if (text[at] == '"') {
                at = endOfString(text, at) - 1;
                continue;
            }
            if (text.compare(at, 2, "//") == 0 || text.compare(at, 2, "/*") == 0) {
                at = skipGaps(text, at) - 1;
                continue;
            }
            if (text[at] == open) {
                ++depth;
            } else if (text[at] == close) {
                --depth;
                if (depth == 0) {
                    return at + 1;
                }
            }
        }
        throw std::runtime_error("config ends inside a value");
    }
    // A number, true, false or null: it runs until the structure resumes.
    while (at < text.size() && text[at] != ',' && text[at] != '}' && text[at] != ']'
        && std::isspace(static_cast<unsigned char>(text[at])) == 0) {
        ++at;
    }
    return at;
}

struct Span {
    std::size_t from = 0;
    std::size_t to = 0;
};

// Where an object's key holds its value, or nothing when the object has no such
// key. `object` is the index of the opening brace.
std::optional<Span> valueOfKey(
    const std::string& text, const std::size_t object, const std::string& key)
{
    std::size_t at = skipGaps(text, object + 1);
    while (at < text.size() && text[at] != '}') {
        if (text[at] != '"') {
            throw std::runtime_error("config has something other than a key in an object");
        }
        const std::size_t nameEnd = endOfString(text, at);
        const std::string name = nlohmann::json::parse(text.substr(at, nameEnd - at))
                                     .get<std::string>();
        std::size_t colon = skipGaps(text, nameEnd);
        if (colon >= text.size() || text[colon] != ':') {
            throw std::runtime_error("config has a key without a value");
        }
        const std::size_t valueStart = skipGaps(text, colon + 1);
        const std::size_t valueEnd = endOfValue(text, valueStart);
        if (name == key) {
            return Span{valueStart, valueEnd};
        }
        at = skipGaps(text, valueEnd);
        if (at < text.size() && text[at] == ',') {
            at = skipGaps(text, at + 1);
        }
    }
    return std::nullopt;
}

// The indentation of the first key of an object, so a key written into it lines
// up with the ones already there.
std::string indentOf(const std::string& text, const std::size_t object)
{
    const std::size_t first = skipGaps(text, object + 1);
    if (first >= text.size() || text[first] == '}') {
        // An empty object: indent one step past the line the brace sits on.
        const std::size_t lineStart = text.rfind('\n', object);
        std::string parent;
        for (std::size_t at = lineStart == std::string::npos ? 0 : lineStart + 1;
            at < text.size() && (text[at] == ' ' || text[at] == '\t'); ++at) {
            parent.push_back(text[at]);
        }
        return parent + std::string(kIndentWidth, ' ');
    }
    const std::size_t lineStart = text.rfind('\n', first);
    if (lineStart == std::string::npos) {
        return std::string(kIndentWidth, ' ');
    }
    std::string indent;
    for (std::size_t at = lineStart + 1; at < first && (text[at] == ' ' || text[at] == '\t');
        ++at) {
        indent.push_back(text[at]);
    }
    return indent;
}

// Writes a key the object did not have, at its top, in the shape the rest of the
// file is written in.
std::string withNewKey(const std::string& text, const std::size_t object, const std::string& key,
    const nlohmann::json& value)
{
    const std::string indent = indentOf(text, object);
    const std::size_t first = skipGaps(text, object + 1);
    const bool empty = first >= text.size() || text[first] == '}';
    std::string entry = "\n" + indent + nlohmann::json(key).dump() + ": " + value.dump();
    if (!empty) {
        entry += ",";
    }
    return text.substr(0, object + 1) + entry + text.substr(object + 1);
}

std::size_t rootObject(const std::string& text)
{
    const std::size_t at = skipGaps(text, 0);
    if (at >= text.size() || text[at] != '{') {
        throw std::runtime_error("config is not a JSON object");
    }
    return at;
}

}  // namespace

std::string configWithValue(
    const std::string& text, const std::vector<std::string>& keys, const nlohmann::json& value)
{
    if (keys.empty()) {
        throw std::runtime_error("no setting named");
    }
    std::string patched = text;
    std::size_t object = rootObject(patched);
    // Walk down to the object that holds the last key, writing the objects the
    // file does not have yet.
    for (std::size_t level = 0; level + 1 < keys.size(); ++level) {
        std::optional<Span> span = valueOfKey(patched, object, keys[level]);
        if (!span.has_value()) {
            patched = withNewKey(patched, object, keys[level], nlohmann::json::object());
            object = rootObject(patched);
            for (std::size_t again = 0; again <= level; ++again) {
                const std::optional<Span> found = valueOfKey(patched, object, keys[again]);
                if (!found.has_value()) {
                    throw std::runtime_error("config lost a key that was just written");
                }
                object = found->from;
            }
            continue;
        }
        if (patched[span->from] != '{') {
            throw std::runtime_error("config setting " + keys[level] + " is not an object");
        }
        object = span->from;
    }

    const std::optional<Span> span = valueOfKey(patched, object, keys.back());
    if (!span.has_value()) {
        return withNewKey(patched, object, keys.back(), value);
    }
    return patched.substr(0, span->from) + value.dump() + patched.substr(span->to);
}

ConfigFile::ConfigFile(fs::path path)
    : path_(std::move(path))
{
}

nlohmann::json ConfigFile::read() const
{
    const std::string text = readWhole(path_);
    // Comments are the operator's notes to themselves; a daemon reads past them.
    return nlohmann::json::parse(text, nullptr, true, true);
}

void ConfigFile::set(const std::vector<std::string>& keys, const nlohmann::json& value)
{
    writeWhole(path_, configWithValue(readWhole(path_), keys, value));
}

}  // namespace bazarish
