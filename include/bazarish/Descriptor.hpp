// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <string>

namespace bazarish {

struct Descriptor {
    std::string fingerprint;
    std::string dest;
    // Seals the card exchange, so a router in between learns neither the card nor whose it is.
    Bytes cardKey;
    std::string name = {};
};

std::string encodeDescriptor(const Descriptor& descriptor);

Descriptor parseDescriptor(const std::string& uri);

inline constexpr char kCardRequestLabel[] = "bazarish card request v1";
inline constexpr char kCardReplyLabel[] = "bazarish card reply v1";

}  // namespace bazarish
