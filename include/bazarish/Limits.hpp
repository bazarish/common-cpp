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

// Cap on a TOKENLESS contact-class payload: the sealed bytes a stranger may
// place in a mailbox without spending anything. It is a protocol constant, not
// an operator's dial - raising it on one server would only invite deliveries
// every other server refuses, and lowering it would break contact requests that
// are correct.
//
// Measured against a real request (CBOR body sealed to the peer's prekey): 3776
// bytes with no greeting, 3910 with a 100-byte greeting and a 32-byte display
// name. Nearly all of it is the 64-token reply batch (2816 bytes of base64) the
// requester hands over so the peer can answer. The cap is that worst case
// rounded up, so a greeting is a greeting - the client holds the user to
// kMaxContactGreetingBytes - and nothing else fits.
constexpr std::size_t kMaxContactRequestBytes = 4096;
// What a user may write into a contact request. A line of hello, not a channel.
constexpr std::size_t kMaxContactGreetingBytes = 100;

}  // namespace bazarish
