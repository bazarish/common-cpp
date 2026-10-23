// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

namespace bazarish {

// SignInWithKey.md, "The consumer": C0, DEL, C1, the line and paragraph separators, bidi controls.
bool isForbiddenCodePoint(unsigned long codePoint);

// The code points of UTF-8 text that carries no forbidden one; none for anything else.
std::optional<std::size_t> plainCodePoints(std::string_view text);

}  // namespace bazarish
