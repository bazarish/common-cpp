// Bazarish project (c) 2026
#include "Invite.hpp"

#include <bazarish/ServerDescriptor.hpp>

namespace bazarish::client {

std::string encodeServerLink(const ServerLink& link)
{
    return encodeServerDescriptor(
        {link.serverFingerprint, link.facadeUrls, link.reseedUrls});
}

ServerLink decodeServerLink(const std::string& uri)
{
    const ServerDescriptor descriptor = parseServerDescriptor(uri);
    ServerLink link;
    link.serverFingerprint = descriptor.fingerprint;
    link.facadeUrls = descriptor.facades;
    link.reseedUrls = descriptor.reseeds;
    return link;
}

}  // namespace bazarish::client
