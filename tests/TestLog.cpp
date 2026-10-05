// Bazarish project (c) 2026
#include "bazarish/Log.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

using namespace bazarish::log;

int main()
{
    CHECK(levelFromString("error") == Level::eError);
    CHECK(levelFromString("warn") == Level::eWarn);
    CHECK(levelFromString("info") == Level::eInfo);
    CHECK(levelFromString("debug") == Level::eDebug);
    CHECK(!levelFromString("verbose").has_value());

    setLevel(Level::eWarn);
    CHECK(level() == Level::eWarn);
    CHECK(enabled(Level::eError));
    CHECK(enabled(Level::eWarn));
    CHECK(!enabled(Level::eInfo));
    CHECK(!enabled(Level::eDebug));

    CHECK(redact("short") == "short");
    CHECK(redact("0123456789abcdef") == "01234567...");

    const std::string path
        = (std::filesystem::temp_directory_path() / "bazarish-testlog.txt").string();
    setComponent("unit");
    setLevel(Level::eDebug);
    const FILE* const redirected = std::freopen(path.c_str(), "w", stderr);
    if (redirected == nullptr) {
        std::printf("FAIL: could not redirect stderr\n");
        return 1;
    }
    info("listening on {}:{}", "127.0.0.1", 8080);
    error("bind failed {}", 13);
    debug("debug line {}", 7);
    setLevel(Level::eWarn);
    info("this line is suppressed");
    std::fflush(stderr);

    std::string captured;
    FILE* const in = std::fopen(path.c_str(), "r");
    if (in == nullptr) {
        std::printf("FAIL: could not reopen capture file\n");
        return 1;
    }
    char buffer[256];
    std::size_t read = 0;
    while ((read = std::fread(buffer, 1, sizeof(buffer), in)) > 0) {
        captured.append(buffer, read);
    }
    std::fclose(in);

    const bool ok = captured.find("unit: listening on 127.0.0.1:8080\n") != std::string::npos
        && captured.find("unit: bind failed 13\n") != std::string::npos
        && captured.find("unit: debug line 7\n") != std::string::npos
        && captured.find("this line is suppressed") == std::string::npos;
    if (!ok) {
        std::printf("FAIL: captured log mismatch:\n%s\n", captured.c_str());
        return 1;
    }
    return 0;
}
