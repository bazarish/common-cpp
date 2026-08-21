// Bazarish project (c) 2026
#pragma once

#include <cstddef>

namespace bazarish {

// Protocol-wide limits: the same numbers on both sides of every exchange, so a
// client never builds what a server will refuse.

// The largest payload one message may carry. It is deliberately small: a
// message is a message, and anything bigger than this is a file, which travels
// client to client and never sits in a mailbox at all. It also bounds what one
// sender can put in someone's mailbox in a single delivery.
constexpr std::size_t kMaxMessagePayloadBytes = 512 * 1024;

}  // namespace bazarish
