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

std::string encodeServerLink(const ServerLink& link);
ServerLink decodeServerLink(const std::string& uri);

}  // namespace bazarish::client
