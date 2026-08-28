// Bazarish project (c) 2026
#include "bazarish/Health.hpp"

#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

#include <fstream>
#include <limits>
#include <string>

namespace bazarish::health {

namespace {

#ifndef _WIN32

// Reads a "VmRSS:"/"VmHWM:"-style kB value from /proc/self/status and returns it
// in bytes; 0 if the field is absent.
std::uint64_t statusFieldBytes(const std::string& field)
{
    std::ifstream status("/proc/self/status");
    if (!status) {
        return 0;
    }
    std::string label;
    while (status >> label) {
        if (label == field) {
            std::uint64_t kib = 0;
            std::string unit;
            if (status >> kib >> unit) {
                return kib * 1024;
            }
            return 0;
        }
        status.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    return 0;
}

#endif

}  // namespace

MemoryUsage processMemoryUsage()
{
    MemoryUsage usage;
#ifdef _WIN32
    // The working set is what this process holds resident, and the same counters
    // carry its peak.
    PROCESS_MEMORY_COUNTERS counters{};
    if (::GetProcessMemoryInfo(::GetCurrentProcess(), &counters, sizeof counters) != 0) {
        usage.current = counters.WorkingSetSize;
        usage.peak = counters.PeakWorkingSetSize;
    }
#else
    usage.current = statusFieldBytes("VmRSS:");
    usage.peak = statusFieldBytes("VmHWM:");
#endif
    return usage;
}

std::string reportJson(const std::string& service, const std::string& version,
    const std::int64_t startedAt, const std::int64_t now, const std::string& extrasJson)
{
    const MemoryUsage memory = processMemoryUsage();
    nlohmann::json report = {
        {"service", service},
        {"version", version},
        {"uptime", now - startedAt},
        {"ramBytes", memory.current},
        {"ramPeakBytes", memory.peak},
    };
    if (!extrasJson.empty()) {
        report.update(nlohmann::json::parse(extrasJson));
    }
    return report.dump();
}

}  // namespace bazarish::health
