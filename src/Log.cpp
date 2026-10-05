// Bazarish project (c) 2026
#include "bazarish/Log.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>

namespace {

std::atomic<bazarish::log::Level> gLevel{bazarish::log::Level::eInfo};
std::string gComponent = "bazarish";
std::mutex gWriteMutex;

// Captured once at static-init time: true when our stderr is wired to the
// journal, in which case systemd parses a leading "<N>" priority prefix.
const bool kUnderJournald = std::getenv("JOURNAL_STREAM") != nullptr;

// Syslog numeric priority for the "<N>" stderr prefix systemd understands.
int syslogPriority(const bazarish::log::Level level)
{
    switch (level) {
        case bazarish::log::Level::eError: return 3;  // LOG_ERR
        case bazarish::log::Level::eWarn:  return 4;  // LOG_WARNING
        case bazarish::log::Level::eInfo:  return 6;  // LOG_INFO
        case bazarish::log::Level::eDebug: return 7;  // LOG_DEBUG
    }
    return 6;
}

std::string_view levelTag(const bazarish::log::Level level)
{
    switch (level) {
        case bazarish::log::Level::eError: return "ERROR";
        case bazarish::log::Level::eWarn:  return "WARN";
        case bazarish::log::Level::eInfo:  return "INFO";
        case bazarish::log::Level::eDebug: return "DEBUG";
    }
    return "INFO";
}

}  // namespace

namespace bazarish::log {

#if !BAZARISH_STD_FORMAT
namespace detail {

std::string fillBraces(const std::string_view fmt, const std::vector<std::string>& args)
{
    std::string out;
    out.reserve(fmt.size());
    std::size_t next = 0;
    for (std::size_t i = 0; i < fmt.size(); ++i) {
        const char c = fmt[i];
        const bool doubled = i + 1 < fmt.size() && fmt[i + 1] == c;
        if ((c == '{' || c == '}') && doubled) {
            out.push_back(c);  // "{{" and "}}" stand for one brace
            ++i;
            continue;
        }
        if (c == '{' && i + 1 < fmt.size() && fmt[i + 1] == '}') {
            out += next < args.size() ? args[next] : std::string();
            ++next;
            ++i;
            continue;
        }
        out.push_back(c);
    }
    return out;
}

}  // namespace detail
#endif


void setComponent(const std::string_view component)
{
    gComponent.assign(component);
}

void setLevel(const Level level)
{
    gLevel.store(level, std::memory_order_relaxed);
}

Level level()
{
    return gLevel.load(std::memory_order_relaxed);
}

std::optional<Level> levelFromString(const std::string_view text)
{
    if (text == "error") {
        return Level::eError;
    }
    if (text == "warn") {
        return Level::eWarn;
    }
    if (text == "info") {
        return Level::eInfo;
    }
    if (text == "debug") {
        return Level::eDebug;
    }
    return std::nullopt;
}

bool enabled(const Level level)
{
    return static_cast<int>(level) <= static_cast<int>(gLevel.load(std::memory_order_relaxed));
}

void emit(const Level level, const std::string_view message)
{
    const std::string line = kUnderJournald
        ? formatLine("<{}>{}: {}\n", syslogPriority(level), gComponent, message)
        : formatLine("{} {}: {}\n", levelTag(level), gComponent, message);
    // stderr is unbuffered, so a single fwrite is one write syscall; the mutex
    // serializes lines from concurrent threads so they never interleave.
    const std::lock_guard<std::mutex> guard(gWriteMutex);
    std::fwrite(line.data(), 1, line.size(), stderr);
}

std::string redact(const std::string_view identifier)
{
    constexpr std::size_t kKeep = 8;
    if (identifier.size() <= kKeep) {
        return std::string(identifier);
    }
    return std::string(identifier.substr(0, kKeep)) + "...";
}

}  // namespace bazarish::log
