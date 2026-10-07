// Bazarish project (c) 2026
#pragma once

#include <string>
#include <vector>

namespace bazarish {

struct PairLink {
    std::string dest;
    std::vector<std::string> reseeds;
};

std::string encodePairLink(const PairLink& link);

PairLink parsePairLink(const std::string& uri);

}  // namespace bazarish
