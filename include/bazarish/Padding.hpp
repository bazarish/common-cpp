// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <cstddef>

namespace bazarish {

inline constexpr std::size_t kPaddingLadder[] = {256, 1024, 4096, 16384};

inline constexpr std::size_t kLengthPrefixBytes = 4;

std::size_t paddedSize(std::size_t length);

Bytes padToLadder(const Bytes& payload, std::size_t ceiling = 0);

Bytes unpadFromLadder(const Bytes& padded);

}  // namespace bazarish
