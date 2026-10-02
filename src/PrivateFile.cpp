// Bazarish project (c) 2026
#include "bazarish/PrivateFile.hpp"

#include <fstream>
#include <iterator>
#include <stdexcept>
#include <system_error>

namespace bazarish {

namespace fs = std::filesystem;

namespace {

// Beside the target, so the rename that puts it in place stays on one filesystem
// and is therefore atomic.
fs::path writtenTemporary(const fs::path& path, const std::string_view bytes)
{
    const fs::path temporary = path.parent_path() / (path.filename().string() + ".tmp");
    std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("failed to open " + temporary.string());
    }
    // An empty marker file is a record too, and the data() of an empty container
    // is a null pointer no stream may be handed.
    if (!bytes.empty()) {
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    out.close();
    if (!out) {
        throw std::runtime_error("failed to write " + temporary.string());
    }
    return temporary;
}

void putInPlace(const fs::path& temporary, const fs::path& path)
{
    std::error_code ec;
    fs::rename(temporary, path, ec);
    if (ec) {
        fs::remove(temporary, ec);
        throw std::runtime_error("cannot put " + path.string() + " in place: " + ec.message());
    }
}

}  // namespace

std::string readFileText(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open " + path.string());
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void writeFileAtomic(const fs::path& path, const std::string_view bytes)
{
    putInPlace(writtenTemporary(path, bytes), path);
}

void writeFileAtomic(const fs::path& path, const Bytes& bytes)
{
    writeFileAtomic(path,
        std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
}

void writePrivateFile(const fs::path& path, const std::string& text)
{
    const fs::path temporary = writtenTemporary(path, text);
    std::error_code ec;
    fs::permissions(temporary, fs::perms::owner_read | fs::perms::owner_write,
        fs::perm_options::replace, ec);
    if (ec) {
        fs::remove(temporary, ec);
        throw std::runtime_error(
            "cannot restrict permissions on " + temporary.string() + ": " + ec.message());
    }
    putInPlace(temporary, path);
}

}  // namespace bazarish
