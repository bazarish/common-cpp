// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            throw testutil::CheckFailure{};                                         \
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
            throw testutil::CheckFailure{};                                             \
        }                                                                               \
    } while (false)

namespace testutil {

// Not a std::exception, so no catch meant for the code under test takes it.
struct CheckFailure {};

inline constexpr std::size_t kDirSuffixBytes = 8;
inline constexpr std::chrono::milliseconds kPollStep{10};
// Only a failing wait spends it whole.
inline constexpr std::chrono::milliseconds kWaitLimit{30000};

inline int failed()
{
    try {
        throw;
    } catch (const CheckFailure&) {
    } catch (const std::exception& error) {
        std::fprintf(stderr, "uncaught exception: %s\n", error.what());
    } catch (...) {
        std::fprintf(stderr, "uncaught exception of an unknown type\n");
    }
    return EXIT_FAILURE;
}

// Empty and named apart, so test trees that run at once never share it.
class ScratchDir {
public:
    explicit ScratchDir(const std::string& tag)
        : path_(std::filesystem::temp_directory_path()
              / ("bazarish-" + tag + "-" + bazarish::toHex(bazarish::randomBytes(kDirSuffixBytes))))
    {
        if (!std::filesystem::create_directories(path_)) {
            throw std::runtime_error("scratch directory exists: " + path_.string());
        }
    }

    ScratchDir(const ScratchDir&) = delete;
    ScratchDir& operator=(const ScratchDir&) = delete;

    ~ScratchDir()
    {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
        if (error) {
            std::fprintf(stderr, "scratch %s stays: %s\n", path_.string().c_str(), error.message().c_str());
        }
    }

    const std::filesystem::path& path() const
    {
        return path_;
    }

private:
    const std::filesystem::path path_;
};

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
