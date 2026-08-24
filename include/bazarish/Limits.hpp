// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <cstdint>

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
// Measured against a real request (CBOR body sealed to the peer's hybrid
// prekey): 8177 bytes with no greeting, 8312 with a 100-byte greeting and a
// 32-byte display name. It is made of the two hybrid sealing keys the bootstrap
// carries (1315 bytes each, of which 1206 is the ML-KEM half), the 64-token
// reply batch (2816 bytes of base64) the requester hands over so the peer can
// answer, and the ML-KEM ciphertext of the seal itself (1088). The cap is that
// worst case rounded up, so a greeting is a greeting - the client holds the
// user to kMaxContactGreetingBytes - and nothing else fits.
constexpr std::size_t kMaxContactRequestBytes = 9216;
// What a user may write into a contact request. A line of hello, not a channel.
constexpr std::size_t kMaxContactGreetingBytes = 100;

// Delivery classes, as the server sees them. The content type is end to end and
// never visible here.
//   content - from a contact, admitted by a one-time token
//   contact - from a stranger, admitted by nothing (a contact request), and
//             therefore the only path with a rate limit on the recipient
//   device  - from the account itself to its own other devices, admitted by the
//             signature on the request that carried it
inline constexpr const char* kContentDeliveryClass = "content";
inline constexpr const char* kContactDeliveryClass = "contact";
inline constexpr const char* kDeviceDeliveryClass = "device";

// How many tokenless contact requests a destination accepts per minute. Real
// ones are a handful in an account's life; the cap is what stops a stranger who
// rotates their own destination from filling a mailbox with them.
//
// Counted on the **destination**, not on the mailbox the envelope names - which
// is what lets the refusal be explicit. A counter keyed by the named mailbox
// would answer differently for a right and a wrong guess, and four messages
// would then confirm that a destination belongs to a given fingerprint. Keyed by
// the destination, under the cap both are "delivered" and over it both are
// "later", so the sender learns their request needs repeating and nothing else.
inline constexpr std::size_t kContactRequestsPerMinute = 3;

// How long a user may delegate their destination to a server for. The ceiling is
// the protocol's, not an operator's: the delegation is what a server needs to
// operate someone's address, so a server that could demand a long one would hold
// a departing user in place. Inside it the client chooses - a short term means
// leaving takes effect sooner, a long one means a client that is away for weeks
// stays reachable.
inline constexpr std::int64_t kMinDelegationDays = 1;
inline constexpr std::int64_t kMaxDelegationDays = 30;
inline constexpr std::int64_t kDefaultDelegationDays = 14;
// The client re-issues at half the term, so a delegation is renewed well before
// it lapses even if the client is only occasionally online.
inline constexpr double kDelegationRenewAtFraction = 0.5;

// How long a registered but unspent delivery-token hash is kept. A token is a
// few dozen bytes and a contact may sit unused for years, so the horizon is
// effectively "as long as the account lives" - it exists so an abandoned
// mailbox's tokens do not accumulate forever. The account's own idle sweep is
// what usually takes them first.
inline constexpr std::int64_t kTokenHashRetentionDays = 10 * 365;

}  // namespace bazarish
