// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <string>

namespace bazarish::health {

// Resident memory of the current process, in bytes. `current` is the live
// resident set; `peak` is the high-water mark over the process lifetime. On Linux
// these come from /proc/self/status (VmRSS / VmHWM), on Windows from the process
// working set; if neither answers both are reported as 0 rather than failing a
// liveness probe.
struct MemoryUsage {
    std::uint64_t current = 0;
    std::uint64_t peak = 0;
};

MemoryUsage processMemoryUsage();

// The shared body of every service's /healthz endpoint: a JSON object
//   {"service","version","uptime","ramBytes","ramPeakBytes"}
// where uptime = now - startedAt (seconds) and the ram fields come from
// processMemoryUsage(). Returned as a string so this header pulls in no JSON
// dependency - which is also why extras arrives as a JSON object already
// serialised: a service adds what only it can report (a facade its load, the
// server its warm pool) and it lands beside the shared fields.
std::string reportJson(const std::string& service, const std::string& version,
    std::int64_t startedAt, std::int64_t now, const std::string& extrasJson = {});

}  // namespace bazarish::health
