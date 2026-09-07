// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <cstddef>

namespace bazarish {

// Length quantisation, shared by every layer that hands opaque bytes to somebody
// who can measure them.
//
// Two such layers exist and they cover different observers. The tunnel pads what
// a facade carries, so a facade measures a step instead of a request. The E2E
// body is padded before it is sealed, so the recipient's server measures a step
// instead of a message - without it the authorship block is a fixed weight and
// the remainder IS the message, which tells a mailbox's server a reaction from a
// receipt from a voice note, and for text the number of bytes that were typed.
//
// Payloads are padded to one of these steps, and to a whole multiple of the last
// one above that.
inline constexpr std::size_t kPaddingLadder[] = {256, 1024, 4096, 16384};

// How the true length is carried inside the padding.
inline constexpr std::size_t kLengthPrefixBytes = 4;

// The size a payload of this length is padded up to, prefix included.
std::size_t paddedSize(std::size_t length);

// Length-prefixed and padded to a step. When `ceiling` is given and no step fits
// under it, the payload is prefixed and left at its own length: a message that
// large is already in a class of its own, and growing it past what the protocol
// admits would refuse it outright.
Bytes padToLadder(const Bytes& payload, std::size_t ceiling = 0);

// The payload back out. Throws when the prefix does not describe what is there.
Bytes unpadFromLadder(const Bytes& padded);

}  // namespace bazarish
