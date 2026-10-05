// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <string>

namespace bazarish {

inline constexpr std::size_t kMaxReactionChars = 4;
inline constexpr std::size_t kMaxReactionBytes = 20;

std::size_t utf8Length(const std::string& text);

bool reactionWithinLimits(const std::string& text);

}  // namespace bazarish
