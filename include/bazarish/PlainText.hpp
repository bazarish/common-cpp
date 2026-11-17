// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace bazarish {

// SignInWithKey.md, "The consumer": C0, DEL, C1, the line and paragraph separators, bidi controls.
bool isForbiddenCodePoint(unsigned long codePoint);

struct Utf8CodePoint {
    unsigned long value;
    std::size_t length;
};

// RFC 3629: none for a truncated, overlong, surrogate or out-of-range sequence.
std::optional<Utf8CodePoint> nextUtf8CodePoint(std::string_view text);

// The code point count; none for invalid UTF-8 or a forbidden code point.
std::optional<std::size_t> plainCodePoints(std::string_view text);

inline constexpr std::size_t kMaxFileNameBytes = 255;

// One plain name that stays in the folder it is saved to.
std::string safeFileName(std::string_view offered);

// Only A-Z change, whatever the locale.
std::string asciiLower(std::string text);

}  // namespace bazarish
