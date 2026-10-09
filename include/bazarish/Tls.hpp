// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <string>

typedef struct ssl_st SSL;

namespace bazarish::tls {

// How a peer is named on a private socket: the hash of the key in its
// certificate, which is what the other side is configured with. A chain and a
// hostname say nothing here, because nothing in the fleet is publicly named.
struct Credential {
    std::filesystem::path certificate;
    std::filesystem::path key;
    std::string pin;
};

// The certificate a service presents, made on first start and kept beside its
// identity. A key of its own: the one that signs operator calls does not go
// into a TLS stack.
Credential selfSigned(const std::filesystem::path& stateDir);

std::string pinOf(SSL* connection);
std::string pinOfCertificate(const std::filesystem::path& certificate);

}  // namespace bazarish::tls
