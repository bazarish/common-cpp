// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <string>

namespace bazarish {

// A contact descriptor: the small, single-QR pointer a contact shares out of
// band (a QR or link). It does NOT carry the contact card — it points at one.
// The recipient fetches and verifies the user-signed contact card for `fp` from
// `srv`, sealing the fetch query to `srvKeyDer` (api/FederatedResolve.md).
struct Descriptor {
    std::string fingerprint;  // the contact's 52-char base32 identity fingerprint
    std::string srv;          // the serving server's .b32.i2p host (where the card is fetched)
    Bytes srvKeyDer;          // that server's serving sealing key, SPKI DER (seals the fetch query)
};

// Encodes the descriptor as a URI:
//   bazarish://invite?v=1&fp=<fingerprint>&srv=<host>&srv_key=<base64url SPKI>
// (the human-readable short form is `fp:b33`, which omits the serving key).
std::string encodeDescriptor(const Descriptor& descriptor);

// Parses a descriptor URI, validating the fingerprint (52-char base32), the
// destination (.b32.i2p) and the serving key (non-empty base64url DER). Throws
// std::invalid_argument on any malformed field.
Descriptor parseDescriptor(const std::string& uri);

}  // namespace bazarish
