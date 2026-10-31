// Bazarish project (c) 2026
#pragma once

#include <string>
#include <vector>

namespace bazarish::client {

struct ServerLink {
    std::string serverFingerprint;
    std::vector<std::string> facades;
    std::vector<std::string> reseedUrls;
};

ServerLink decodeServerLink(const std::string& uri);

}  // namespace bazarish::client
