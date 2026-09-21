// Bazarish project (c) 2026
#include "bazarish/PrivateFile.hpp"

#include <fstream>
#include <iterator>
#include <stdexcept>
#include <system_error>

namespace bazarish {

namespace fs = std::filesystem;

std::string readFileText(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open " + path.string());
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void writePrivateFile(const fs::path& path, const std::string& text)
{
    const fs::path temporary = path.parent_path() / (path.filename().string() + ".tmp");
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("failed to open " + temporary.string());
        }
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
        out.close();
        if (!out) {
            throw std::runtime_error("failed to write " + temporary.string());
        }
    }
    std::error_code ec;
    fs::permissions(temporary, fs::perms::owner_read | fs::perms::owner_write,
        fs::perm_options::replace, ec);
    if (ec) {
        fs::remove(temporary, ec);
        throw std::runtime_error(
            "cannot restrict permissions on " + temporary.string() + ": " + ec.message());
    }
    fs::rename(temporary, path, ec);
    if (ec) {
        fs::remove(temporary, ec);
        throw std::runtime_error("cannot put " + path.string() + " in place: " + ec.message());
    }
}

}  // namespace bazarish
