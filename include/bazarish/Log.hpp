// Bazarish project (c) 2026
#pragma once

#include <optional>
#include <chrono>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

// libstdc++ 13 is the first with <format>; Debian 12 ships 12, where the same
// lines have to be assembled by hand. Everything this project logs uses plain
// "{}" placeholders, so that is all the fallback fills in - and only the
// compile-time checking of the format against its arguments is given up.
#if __has_include(<format>)
#    include <format>
#    define BAZARISH_STD_FORMAT 1
#else
#    include <sstream>
#    include <vector>
#    define BAZARISH_STD_FORMAT 0
#endif

namespace bazarish::log {

// Severity levels, ordered from most to least severe. The numeric order is
// load-bearing: a level passes the threshold when it is at least as severe as
// the configured minimum.
enum class Level {
    eError,
    eWarn,
    eInfo,
    eDebug,
};

// Set once at startup, before any worker threads start. Prefixes every line
// emitted by this process (e.g. "server-core").
void setComponent(std::string_view component);

// Process-wide minimum severity. Lines below it are dropped. Default is eInfo.
void setLevel(Level level);
Level level();

// Parses "error" | "warn" | "info" | "debug"; nullopt for anything else.
std::optional<Level> levelFromString(std::string_view text);

// True when a line at this level passes the current threshold.
bool enabled(Level level);

// Emits one fully-formatted line to stderr as a single write (thread-safe, no
// interleaving). Under systemd ($JOURNAL_STREAM set) the line carries a "<N>"
// syslog-priority prefix so journald records the correct severity; otherwise
// it carries a human-readable level tag. Most call sites use the level helpers
// below instead of calling this directly.
void emit(Level level, std::string_view message);

// Shortens an identifier (fingerprint, destination) for debug diagnostics:
// keeps a short prefix and elides the rest. This is NOT a tool to make message
// content safe to log - content must never be logged at all.
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

// One argument as text, the way std::format would write it.
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

// Replaces each "{}" with the next argument. "{{" and "}}" are the escapes
// std::format uses, and are honoured here for the same reason.
std::string fillBraces(std::string_view fmt, const std::vector<std::string>& args);

}  // namespace detail

template <typename... Args>
std::string formatLine(std::string_view fmt, Args&&... args)
{
    return detail::fillBraces(fmt, {detail::asText(args)...});
}
#endif

// Type-safe, level-gated entry points. Where the standard library has it,
// std::format_string checks the format against its arguments at compile time;
// formatting is skipped entirely when the level is suppressed.
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

// Says how long a stretch of work took, but only when it took long enough to
// matter. What it is for: a thread that others queue behind, where the question
// is never "how fast is this" but "which of these is the one being waited out".
// Silent below the bound it is given, so it can be left in place.
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
