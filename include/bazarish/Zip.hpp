// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <string>
#include <vector>

namespace bazarish {

inline constexpr unsigned kOwnerOnlyMode = 0600;

struct ZipEntry {
    std::string name;
    Bytes data;
    unsigned mode = kOwnerOnlyMode;
};

Bytes zipStored(const std::vector<ZipEntry>& entries);
std::vector<ZipEntry> unzipStored(const Bytes& archive);

}  // namespace bazarish
