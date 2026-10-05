// Bazarish project (c) 2026
#pragma once

#include <string>
#include <vector>

namespace bazarish {

struct ServerDescriptor {
    std::string fingerprint;           // 52-char base32 server fingerprint
    std::vector<std::string> facades;
    std::vector<std::string> reseeds;
};

bool isI2pFacadeUrl(const std::string& url);

void setAllowFacadeWithoutI2pForDevPurposes(bool allow);
bool allowFacadeWithoutI2pForDevPurposes();

void setSelfHostedFacadeOnLoopback(bool own);
bool selfHostedFacadeOnLoopback();

std::string encodeServerDescriptor(const ServerDescriptor& descriptor);

ServerDescriptor parseServerDescriptor(const std::string& uri);

}  // namespace bazarish
