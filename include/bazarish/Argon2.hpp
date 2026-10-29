// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <cstddef>
#include <cstdint>

namespace bazarish {

struct Argon2Cost {
    std::uint32_t memoryKiB = 0;
    std::uint32_t passes = 0;
    std::uint32_t lanes = 0;
};

// Argon2id (RFC 9106) through OpenSSL; throws when this OpenSSL lacks it.
Bytes argon2id(const Bytes& pass, const Bytes& salt, const Argon2Cost& cost, std::size_t outBytes);

}  // namespace bazarish
