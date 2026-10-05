// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <cstddef>
#include <string>

namespace bazarish {

inline constexpr std::size_t kViewCapabilityBytes = 16;
inline constexpr std::size_t kViewCapabilityChars = kViewCapabilityBytes * 2;
bool isViewCapability(const std::string& text);

struct Descriptor {
    std::string fingerprint;
    std::string dest;
    std::string view;
    std::string name = {};
};

std::string encodeDescriptor(const Descriptor& descriptor);

Descriptor parseDescriptor(const std::string& uri);

}  // namespace bazarish
