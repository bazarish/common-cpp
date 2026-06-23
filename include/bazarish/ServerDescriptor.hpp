// Bazarish project (c) 2026
#pragma once

#include <string>
#include <vector>

namespace bazarish {

// A server-configuration descriptor: the messaging server's fingerprint plus its
// facade URLs, so a client can add a server from one link or QR with no manual
// host/port/fingerprint entry. The fingerprint is the trust anchor; everything
// the server signs is verified against it. This is the only artifact that carries
// facade URLs, and it is meant only for a server's own clients (api/Facade.md).
struct ServerDescriptor {
    std::string fingerprint;           // 52-char base32 server fingerprint
    std::vector<std::string> facades;  // facade URLs, in client failover order
};

// Encodes the descriptor as a human-readable URI (no base64 - every field is
// legible at a glance):
//   bazarish://server?v=1&fp=<fingerprint>&facade=<url>[&facade=<url>...]
// Facade URLs ride verbatim, so they must not contain '&'.
std::string encodeServerDescriptor(const ServerDescriptor& descriptor);

// Parses such a URI, validating the version and the 52-char base32 fingerprint
// and collecting facade URLs in order. Unknown keys are ignored for forward
// compatibility. Throws std::invalid_argument on any malformed field.
ServerDescriptor parseServerDescriptor(const std::string& uri);

}  // namespace bazarish
