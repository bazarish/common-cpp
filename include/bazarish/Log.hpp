// Bazarish project (c) 2026
#pragma once

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

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
// content safe to log — content must never be logged at all.
std::string redact(std::string_view identifier);

// Type-safe, level-gated entry points. std::format_string checks the format
// against its arguments at compile time; formatting is skipped entirely when
// the level is suppressed.
template <typename... Args>
void error(std::format_string<Args...> fmt, Args&&... args)
{
    if (enabled(Level::eError)) {
        emit(Level::eError, std::format(fmt, std::forward<Args>(args)...));
    }
}

template <typename... Args>
void warn(std::format_string<Args...> fmt, Args&&... args)
{
    if (enabled(Level::eWarn)) {
        emit(Level::eWarn, std::format(fmt, std::forward<Args>(args)...));
    }
}

template <typename... Args>
void info(std::format_string<Args...> fmt, Args&&... args)
{
    if (enabled(Level::eInfo)) {
        emit(Level::eInfo, std::format(fmt, std::forward<Args>(args)...));
    }
}

template <typename... Args>
void debug(std::format_string<Args...> fmt, Args&&... args)
{
    if (enabled(Level::eDebug)) {
        emit(Level::eDebug, std::format(fmt, std::forward<Args>(args)...));
    }
}

}  // namespace bazarish::log
