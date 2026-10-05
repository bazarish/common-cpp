// Bazarish project (c) 2026
#pragma once

#include <optional>
#include <chrono>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#if __has_include(<format>)
#    include <format>
#    define BAZARISH_STD_FORMAT 1
#else
#    include <sstream>
#    include <vector>
#    define BAZARISH_STD_FORMAT 0
#endif

namespace bazarish::log {

enum class Level {
    eError,
    eWarn,
    eInfo,
    eDebug,
};

void setComponent(std::string_view component);

void setLevel(Level level);
Level level();

std::optional<Level> levelFromString(std::string_view text);

bool enabled(Level level);

void emit(Level level, std::string_view message);

std::string redact(std::string_view identifier);

#if BAZARISH_STD_FORMAT
template <typename... Args>
using FormatString = std::format_string<Args...>;

template <typename... Args>
std::string formatLine(FormatString<Args...> fmt, Args&&... args)
{
    return std::format(fmt, std::forward<Args>(args)...);
}
#else
template <typename... Args>
using FormatString = std::string_view;

namespace detail {

template <typename T>
std::string asText(const T& value)
{
    if constexpr (std::is_same_v<std::decay_t<T>, bool>) {
        return value ? "true" : "false";
    } else if constexpr (std::is_convertible_v<T, std::string_view>) {
        return std::string(std::string_view(value));
    } else {
        std::ostringstream out;
        out << value;
        return out.str();
    }
}

std::string fillBraces(std::string_view fmt, const std::vector<std::string>& args);

}  // namespace detail

template <typename... Args>
std::string formatLine(std::string_view fmt, Args&&... args)
{
    return detail::fillBraces(fmt, {detail::asText(args)...});
}
#endif

template <typename... Args>
void error(FormatString<Args...> fmt, Args&&... args)
{
    if (enabled(Level::eError)) {
        emit(Level::eError, formatLine(fmt, std::forward<Args>(args)...));
    }
}

template <typename... Args>
void warn(FormatString<Args...> fmt, Args&&... args)
{
    if (enabled(Level::eWarn)) {
        emit(Level::eWarn, formatLine(fmt, std::forward<Args>(args)...));
    }
}

template <typename... Args>
void info(FormatString<Args...> fmt, Args&&... args)
{
    if (enabled(Level::eInfo)) {
        emit(Level::eInfo, formatLine(fmt, std::forward<Args>(args)...));
    }
}

template <typename... Args>
void debug(FormatString<Args...> fmt, Args&&... args)
{
    if (enabled(Level::eDebug)) {
        emit(Level::eDebug, formatLine(fmt, std::forward<Args>(args)...));
    }
}

class Slow {
public:
    Slow(std::string what, const std::chrono::milliseconds report)
        : what_(std::move(what))
        , report_(report)
        , startedAt_(std::chrono::steady_clock::now())
    {
    }
    ~Slow()
    {
        const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startedAt_);
        if (took >= report_) {
            info("{} took {} ms", what_, static_cast<long long>(took.count()));
        }
    }
    Slow(const Slow&) = delete;
    Slow& operator=(const Slow&) = delete;

private:
    const std::string what_;
    const std::chrono::milliseconds report_;
    const std::chrono::steady_clock::time_point startedAt_;
};

}  // namespace bazarish::log
