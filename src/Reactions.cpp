// Bazarish project (c) 2026
#include "bazarish/Reactions.hpp"

namespace bazarish {

std::size_t utf8Length(const std::string& text)
{
    std::size_t count = 0;
    for (const char raw : text) {
        if ((static_cast<unsigned char>(raw) & 0xC0) != 0x80) {
            ++count;
        }
    }
    return count;
}

bool reactionWithinLimits(const std::string& text)
{
    return text.size() <= kMaxReactionBytes && utf8Length(text) <= kMaxReactionChars;
}

}  // namespace bazarish
