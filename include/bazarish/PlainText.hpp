// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace bazarish {

// SignInWithKey.md, "The consumer": C0, DEL, C1, the line and paragraph separators, bidi controls.
bool isForbiddenCodePoint(unsigned long codePoint);

// The code points of UTF-8 text that carries no forbidden one; none for anything else.
std::optional<std::size_t> plainCodePoints(std::string_view text);

inline constexpr std::size_t kMaxFileNameBytes = 255;

// A file name a peer offered, as one plain name that stays in the folder it is saved to.
std::string safeFileName(std::string_view offered);

}  // namespace bazarish
