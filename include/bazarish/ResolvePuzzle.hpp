// Bazarish project (c) 2026
#pragma once

#include "bazarish/Argon2.hpp"
#include "bazarish/Bytes.hpp"

#include <cstdint>

namespace bazarish {

// About 4 ms per evaluation on a Cortex-A76 and on a desktop core (measured 2026-10-29).
inline constexpr Argon2Cost kPuzzleCost{4096, 1, 1};
inline constexpr std::size_t kPuzzleDigestBytes = 32;
inline constexpr std::uint32_t kMaxPuzzleBits = 14;
inline constexpr const char* kProofRequiredCode = "PROOF_REQUIRED";

// Whether Argon2id over the nonce, salted with the stamp, starts with `bits` zero bits.
bool puzzleSolved(const Bytes& stamp, std::uint64_t nonce, std::uint32_t bits);

std::uint64_t solvePuzzle(const Bytes& stamp, std::uint32_t bits, unsigned threads);

}  // namespace bazarish
