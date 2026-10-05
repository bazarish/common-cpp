// Bazarish project (c) 2026
#pragma once

#include <string>
#include <vector>

namespace bazarish::client {

struct QrSymbol {
    int width = 0;
    std::vector<unsigned char> modules;
};

std::vector<QrSymbol> encodeQrSymbols(const std::string& payload);

std::vector<std::string> renderQrCodes(const std::string& payload);

}  // namespace bazarish::client
