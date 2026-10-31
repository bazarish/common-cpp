// Bazarish project (c) 2026
#include "Invite.hpp"

#include <bazarish/ServerDescriptor.hpp>

namespace bazarish::client {

ServerLink decodeServerLink(const std::string& uri)
{
    const ServerDescriptor descriptor = parseServerDescriptor(uri);
    ServerLink link;
    link.serverFingerprint = descriptor.fingerprint;
    link.facades = descriptor.facades;
    link.reseedUrls = descriptor.reseeds;
    return link;
}

}  // namespace bazarish::client
