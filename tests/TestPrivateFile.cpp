// Bazarish project (c) 2026
#include "bazarish/PrivateFile.hpp"

#include "TestUtil.hpp"

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

using namespace bazarish;

namespace fs = std::filesystem;

namespace {

constexpr fs::perms kOwnerOnly = fs::perms::owner_read | fs::perms::owner_write;
constexpr fs::perms kGroupReadable = kOwnerOnly | fs::perms::group_read;
constexpr int kRacingWrites = 100;

#ifndef _WIN32
fs::perms permsOf(const fs::path& file)
{
    return fs::status(file).permissions() & fs::perms::all;
}
#endif

}  // namespace

int main()
{
    const fs::path root = testutil::freshDir("test-private-file");
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

    writePrivateFile(key, "rotated");
    CHECK(readFileText(key) == "rotated");

    const fs::path config = root / "config.json";
    writeFileAtomic(config, std::string_view("{}"), kGroupReadable);
    writeFileAtomic(config, std::string_view("{\"a\": 1}"), fs::status(config).permissions());
    CHECK(readFileText(config) == "{\"a\": 1}");
#ifndef _WIN32
    CHECK(permsOf(config) == kGroupReadable);
#endif

    {
        const fs::path shared = root / "shared.json";
        const std::string first(4096, 'a');
        const std::string second(8192, 'b');
        std::atomic<int> failed{0};
        const auto writer = [&shared, &failed](const std::string& text) {
            for (int i = 0; i < kRacingWrites; ++i) {
                try {
                    writeFileAtomic(shared, std::string_view(text), kOwnerOnly);
                } catch (const std::exception&) {
                    ++failed;
                }
            }
        };
        std::thread one(writer, first);
        std::thread two(writer, second);
        one.join();
        two.join();
        CHECK(failed.load() == 0);
        const std::string landed = readFileText(shared);
        CHECK(landed == first || landed == second);
        std::size_t left = 0;
        for (const fs::directory_entry& entry : fs::directory_iterator(root)) {
            const std::string name = entry.path().filename().string();
            left += name.starts_with("shared.json.") ? 1 : 0;
        }
        CHECK(left == 0);
    }

    writePrivateFile(root / "bytes.bin", std::string("\0\x01\xFF", 3));
    CHECK(readFileBytes(root / "bytes.bin") == (Bytes{0x00, 0x01, 0xFF}));
    bool named = false;
    try {
        (void)readFileBytes(root / "absent.bin");
    } catch (const std::exception& error) {
        named = std::string(error.what()).find("absent.bin") != std::string::npos;
    }
    CHECK(named);

    fs::remove_all(root);
    std::fprintf(stderr, "TestPrivateFile passed\n");
    return 0;
}
