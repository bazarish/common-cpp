// Bazarish project (c) 2026
#pragma once

#include <string>

namespace bazarish {

struct Descriptor {
    std::string fingerprint;
    std::string dest;
    std::string name = {};
};

std::string encodeDescriptor(const Descriptor& descriptor);

Descriptor parseDescriptor(const std::string& uri);

}  // namespace bazarish
