// Bazarish project (c) 2026
#pragma once

#include <string>
#include <vector>

namespace bazarish {

// A server-configuration descriptor: the messaging server's fingerprint plus the
// two kinds of address a client needs, so a server can be added from one link or
// QR with no manual host/port/fingerprint entry. The fingerprint is the trust
// anchor; everything the server signs is verified against it. This is the only
// artifact that carries these addresses, and it is meant only for a server's own
// clients (api/Facade.md).
//
// The two kinds are not interchangeable, which is why they are separate fields:
//
//   facade - where the client talks to the server. Always an I2P address, because
//            that is the only way the client ever speaks to it.
//   reseed - where a client with no I2P yet fetches a slice of netdb to start its
//            router from. Never an I2P address: nothing could reach it. It answers
//            that one request and carries no API.
struct ServerDescriptor {
    std::string fingerprint;           // 52-char base32 server fingerprint
    std::vector<std::string> facades;  // .b32.i2p facade URLs, in failover order
    std::vector<std::string> reseeds;  // clearnet URLs, for bootstrapping I2P only
};

// True when the URL's host ends in .b32.i2p - the one thing that decides which
// list an address belongs in.
bool isI2pFacadeUrl(const std::string& url);

// Encodes the descriptor as a human-readable URI (no base64 - every field is
// legible at a glance):
//   bazarish://server?v=1&fp=<fingerprint>&facade=<url>[&facade=...][&reseed=<url>...]
// URLs ride verbatim, so they must not contain '&'.
std::string encodeServerDescriptor(const ServerDescriptor& descriptor);

// Parses such a URI, validating the version and the 52-char base32 fingerprint
// and collecting the two lists in order. A facade that is not an I2P address, or
// a reseed that is one, is refused: taking either would mean talking to a server
// over a transport this protocol does not use, or bootstrapping from an address
// that cannot be reached before there is a router. Unknown keys are ignored for
// forward compatibility. Throws std::invalid_argument on any malformed field.
ServerDescriptor parseServerDescriptor(const std::string& uri);

}  // namespace bazarish
