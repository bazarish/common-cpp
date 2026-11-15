// Bazarish project (c) 2026
#pragma once

#include "bazarish/SecretBytes.hpp"

#include <string>
#include <vector>

namespace bazarish {

struct PairLink {
    std::string dest;
    std::vector<std::string> reseeds;
    // Seals the hello and the account, so a gateway between the devices reads neither.
    SecretBytes key;
};

std::string encodePairLink(const PairLink& link);

PairLink parsePairLink(const std::string& uri);

}  // namespace bazarish
