// Bazarish project (c) 2026
#pragma once

#include <string>
#include <vector>

namespace bazarish::client {

// One QR symbol as a square module grid: modules[y * width + x] is 1 for a
// dark module, 0 for light. The quiet zone is not included.
struct QrSymbol {
    int width = 0;
    std::vector<unsigned char> modules;
};

// Encodes payload as a structured-append sequence of QR symbols. A large
// payload (the full invite chain) spans several symbols that a scanner
// reassembles into the original data.
std::vector<QrSymbol> encodeQrSymbols(const std::string& payload);

// Renders the same sequence with terminal block characters: each returned
// string is one complete symbol, ready to print.
std::vector<std::string> renderQrCodes(const std::string& payload);

}  // namespace bazarish::client
