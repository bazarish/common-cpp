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
// How many contact requests may sit unfetched in one mailbox. The per-minute
// limit bounds the rate; this bounds the pile, so an address that is being
// hammered stops taking requests instead of holding a day of them. A sender is
// told to come back, the way a rate-limited one is.
constexpr std::size_t kMaxPendingContactRequests = 30;

// The cap on a tokenless contact request, in delivered (sealed) bytes. It is the
// one thing a stranger may put in a mailbox, so it is the measured worst case and
// not a generous number: room above what a request can weigh is room to fill a
// mailbox with.
//
// Measured at 10947 bytes: the two hybrid sealing keys the bootstrap carries, the
// delivery pass the requester hands over so the peer can answer, the ML-KEM
// ciphertext of the seal, the authorship block with the sender's keys in it (a
// request has no card and no pass, so the signature is the only thing that names
// them), the longest greeting a user may write and the longest name an account
// may carry. The 32 bytes on top are what the variable-length parts can add: an
// ECDSA signature is 70 to 72 bytes and a CBOR integer is as wide as its value.
constexpr std::size_t kMaxContactRequestBytes = 10979;
// What a user may write into a contact request. A line of hello, not a channel.
constexpr std::size_t kMaxContactGreetingBytes = 100;
// An account's own display name, in bytes. It rides in a contact request as the
// label the recipient seeds their contact with, and that request is the one thing
// a stranger may put in a mailbox - so the name is bounded here, or the size of
// that request would not be. Counted in bytes and not characters because that is
// what a mailbox holds; 64 leaves about 32 characters of a non-Latin alphabet.
constexpr std::size_t kMaxAccountNameBytes = 64;

// Delivery classes, as the server sees them. The content type is end to end and
// never visible here.
//   content - from a contact, admitted by the pass they were given
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

// How many delivery passes one request may register, and how many a mailbox may
// hold at once. A pass is one per correspondent and never expires, so both sit
// far above any real address book. They are what bounds the capability directory
// of a mailbox at all: token registration was bounded by nothing, and a single
// test account accumulated sixty-one thousand of them.
inline constexpr std::size_t kMaxPassesPerRequest = 256;
inline constexpr std::size_t kMaxPassesPerMailbox = 4096;

}  // namespace bazarish
