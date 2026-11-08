// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

#define CHECK_THROWS(expression)                                                        \
    do {                                                                                \
        bool thrown = false;                                                            \
        try {                                                                           \
            (void)(expression);                                                         \
        } catch (const std::exception&) {                                               \
            thrown = true;                                                              \
        }                                                                               \
        if (!thrown) {                                                                  \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d: %s did not throw\n",    \
                __FILE__, __LINE__, #expression);                                       \
            std::exit(1);                                                               \
        }                                                                               \
    } while (false)

namespace testutil {

inline constexpr std::size_t kDirSuffixBytes = 8;
inline constexpr std::chrono::milliseconds kPollStep{10};
// Long enough for anything a test waits on in-process; only a failing wait spends it whole.
inline constexpr std::chrono::milliseconds kWaitLimit{30000};

// Empty and named apart, so test trees that run at once never share it.
inline std::filesystem::path freshDir(const std::string& tag)
{
    const std::filesystem::path dir = std::filesystem::temp_directory_path()
        / ("bazarish-" + tag + "-" + bazarish::toHex(bazarish::randomBytes(kDirSuffixBytes)));
    std::filesystem::create_directories(dir);
    return dir;
}

inline bool waitFor(
    const std::function<bool()>& condition, const std::chrono::milliseconds limit = kWaitLimit)
{
    const auto until = std::chrono::steady_clock::now() + limit;
    while (!condition()) {
        if (std::chrono::steady_clock::now() >= until) {
            return false;
        }
        std::this_thread::sleep_for(kPollStep);
    }
    return true;
}

}  // namespace testutil
