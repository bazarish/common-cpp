// Bazarish project (c) 2026
#include "bazarish/PrivateFile.hpp"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <system_error>

namespace bazarish {

namespace fs = std::filesystem;

namespace {

[[noreturn]] void failedToSync(const fs::path& path, const int error)
{
    throw std::runtime_error("cannot flush " + path.string() + " to disk: " + std::strerror(error));
}

#ifndef _WIN32
void flushOpened(const fs::path& path, const int flags)
{
    const int fd = ::open(path.c_str(), flags | O_CLOEXEC);
    if (fd < 0) {
        failedToSync(path, errno);
    }
    const int synced = ::fsync(fd);
    const int syncError = errno;
    const int closed = ::close(fd);
    if (synced != 0) {
        failedToSync(path, syncError);
    }
    if (closed != 0) {
        failedToSync(path, errno);
    }
}
#endif

void syncFile(const fs::path& path)
{
#ifdef _WIN32
    const int fd = ::_wopen(path.c_str(), _O_WRONLY | _O_BINARY);
    if (fd < 0) {
        failedToSync(path, errno);
    }
    const int synced = ::_commit(fd);
    const int syncError = errno;
    const int closed = ::_close(fd);
    if (synced != 0) {
        failedToSync(path, syncError);
    }
    if (closed != 0) {
        failedToSync(path, errno);
    }
#else
    flushOpened(path, O_RDONLY);
#endif
}

fs::path writtenTemporary(const fs::path& path, const std::string_view bytes)
{
    const fs::path temporary = path.parent_path() / (path.filename().string() + ".tmp");
    std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("failed to open " + temporary.string());
    }
    if (!bytes.empty()) {
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    out.close();
    if (!out) {
        throw std::runtime_error("failed to write " + temporary.string());
    }
    syncFile(temporary);
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
    const fs::path parent = path.parent_path();
    syncDirectory(parent.empty() ? fs::path(".") : parent);
}

}  // namespace

void syncDirectory(const fs::path& directory)
{
#ifdef _WIN32
    // Windows has no directory fsync; NTFS journals the rename itself.
    static_cast<void>(directory);
#else
    flushOpened(directory, O_RDONLY | O_DIRECTORY);
#endif
}

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
