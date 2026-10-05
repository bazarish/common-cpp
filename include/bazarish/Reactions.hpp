// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <string>

namespace bazarish {

// A reaction is a glyph, not a message: it rides the same envelope as everything
// else and appears as a chip on someone else's message, so it is bounded on both
// counts. Four characters is enough for an emoji with a modifier or a zero-width
// joiner pair; twenty bytes is what four of the longest UTF-8 sequences plus
// their joiners take. Both are checked on send and again on receipt, because a
// peer's client is not ours to trust.
inline constexpr std::size_t kMaxReactionChars = 4;
inline constexpr std::size_t kMaxReactionBytes = 20;

// Counts UTF-8 characters (code points), not bytes.
std::size_t utf8Length(const std::string& text);

// Whether `text` is within both limits. An empty text is valid: it removes the
// sender's reaction.
bool reactionWithinLimits(const std::string& text);

}  // namespace bazarish
