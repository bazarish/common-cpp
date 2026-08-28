// Bazarish project (c) 2026
#pragma once

#include <string>
#include <vector>

namespace bazarish::client {

// The contact invite is a small descriptor (bazarish://invite?fp&srv&srv_key) -
// see common bazarish/Descriptor.hpp (encodeDescriptor/parseDescriptor). This
// header now carries only the server-configuration link.

// A server-configuration link: a server fingerprint plus its facade URLs, so a
// client can add the server with all its settings from one link / QR - no manual
// host/port/fingerprint entry. (The fingerprint is the trust anchor; everything
// the server signs is verified against it as usual.)
struct ServerLink {
    std::string serverFingerprint;
    // I2P addresses: where the client talks to the server.
    std::vector<std::string> facadeUrls;
    // Clearnet addresses: where a client with no router yet asks for a slice of
    // netdb, and nothing else.
    std::vector<std::string> reseedUrls;
};

// Encodes a server link as the human-readable URI
// bazarish://server?v=1&fp=<fp>&facade=<url>... (see common ServerDescriptor.hpp).
std::string encodeServerLink(const ServerLink& link);
// Decodes such a URI. Throws on a malformed URI or payload.
ServerLink decodeServerLink(const std::string& uri);

}  // namespace bazarish::client
