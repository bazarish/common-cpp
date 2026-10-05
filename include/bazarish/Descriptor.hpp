// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <cstddef>
#include <string>

namespace bazarish {

// The card-read capability a server issues per user: 16 random bytes, carried as
// hex. Long enough that it cannot be guessed, short enough to keep a descriptor
// in one QR frame.
inline constexpr std::size_t kViewCapabilityBytes = 16;
inline constexpr std::size_t kViewCapabilityChars = kViewCapabilityBytes * 2;
bool isViewCapability(const std::string& text);

// A contact descriptor: the small, single-QR pointer a contact shares out of
// band (a QR or link). It does NOT carry the contact card - it points at one.
// The recipient fetches and verifies the user-signed contact card for `fp` at
// `dest`, sealing the fetch query to `keyDer`.
//
// `dest` is the user's own destination, not a server's, and `view` is a capability
// the server issued for reading that user's card: holding it is what proves a
// fetcher was given this descriptor, which is why the card fetch asks for it
// back. It is not a key - it encrypts nothing - so it can be rotated to retire
// old invites without touching anything the delivery path depends on.
struct Descriptor {
    std::string fingerprint;  // the contact's 52-char base32 identity fingerprint
    std::string dest;         // the user's own .b32.i2p destination (where the card is fetched)
    std::string view;         // card-read capability, 32 hex characters
    // Optional human display name the inviter advertises (percent-encoded on the
    // wire). The recipient adopts it as the contact's local display name; it is a
    // one-time label set at add time, never re-fetched or transmitted afterwards.
    // Defaulted so existing 3-field aggregate initializers stay valid.
    std::string name = {};
};

// Encodes the descriptor as a URI:
//   bazarish://invite?v=1&fp=<fingerprint>&dest=<host>&view=<32 hex>[&name=<percent-encoded>]
// (the human-readable short form is `fp:b33`, which omits the serving key).
std::string encodeDescriptor(const Descriptor& descriptor);

// Parses a descriptor URI, validating the fingerprint (52-char base32), the
// destination (.b32.i2p) and the view capability (32 hex characters). The
// optional name is percent-decoded. Throws std::invalid_argument on any
// malformed required field.
Descriptor parseDescriptor(const std::string& uri);

}  // namespace bazarish
