// Bazarish project (c) 2026
#include "bazarish/PrivateFile.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>

using namespace bazarish;

namespace fs = std::filesystem;

namespace {

constexpr fs::perms kOwnerOnly = fs::perms::owner_read | fs::perms::owner_write;
constexpr fs::perms kGroupReadable = kOwnerOnly | fs::perms::group_read;

#ifndef _WIN32
fs::perms permsOf(const fs::path& file)
{
    return fs::status(file).permissions() & fs::perms::all;
}
#endif

}  // namespace

int main()
{
    const fs::path root = fs::temp_directory_path() / "bazarish-test-private-file";
    fs::remove_all(root);
    fs::create_directories(root);

    const fs::path key = root / "key.pem";
    {
        std::ofstream stale(root / "key.pem.tmp");
        stale << "left by a crash";
    }
    fs::permissions(root / "key.pem.tmp", fs::perms::all, fs::perm_options::replace);
    writePrivateFile(key, "secret");
    CHECK(readFileText(key) == "secret");
#ifndef _WIN32
    CHECK(permsOf(key) == kOwnerOnly);
#endif
    CHECK(!fs::exists(root / "key.pem.tmp"));

    writePrivateFile(key, "rotated");
    CHECK(readFileText(key) == "rotated");

    const fs::path config = root / "config.json";
    writeFileAtomic(config, std::string_view("{}"), kGroupReadable);
    writeFileAtomic(config, std::string_view("{\"a\": 1}"), fs::status(config).permissions());
    CHECK(readFileText(config) == "{\"a\": 1}");
#ifndef _WIN32
    CHECK(permsOf(config) == kGroupReadable);
#endif

    fs::remove_all(root);
    std::fprintf(stderr, "TestPrivateFile passed\n");
    return 0;
}
