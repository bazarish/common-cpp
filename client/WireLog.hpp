// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish::client {

// What this account said on the wire and what came back, kept in memory for the
// connection log. It exists because the alternatives answer nothing: the log on
// stderr is not there in a packaged build, and a message bubble says "sent"
// without saying who agreed to it.
//
// One of these belongs to one account. Events arrive from the courier's threads,
// the sync thread and the network thread, so every call takes the lock.
//
// What a line may carry: a kind, a path, a status, a delivery id, the first
// characters of a correspondent's fingerprint. Never message text, never a full
// fingerprint or destination - this is a window a user may screenshot into a bug
// report.
struct WireEvent {
    std::int64_t atMillis = 0;
    // Whether this account sent it or received it.
    bool outgoing = true;
    // The subject: "text to Bob (a1b2c3)", "POST /v1/messaging/tokens",
    // "self device.account-name".
    std::string what;
    // Where it got to: an HTTP status, "sending", "stored", "failed: NO_TOKEN".
    std::string status;
    // Anything that helps and fits: size, elapsed time, a delivery id.
    std::string detail;
};

// How much history the window shows. Small on purpose: this is the tail of what
// just happened, not a journal, and the empty long-polls that would flood it are
// not recorded at all.
inline constexpr std::size_t kWireLogCapacity = 100;

class WireLog {
public:
    void record(WireEvent event);
    // Oldest first, as it happened.
    std::vector<WireEvent> snapshot() const;
    void clear();

private:
    mutable std::mutex mutex_;
    std::deque<WireEvent> events_;
};

}  // namespace bazarish::client
