// Bazarish project (c) 2026
#include "bazarish/PlainText.hpp"

#include <openssl/asn1.h>

#include <algorithm>
#include <array>

namespace bazarish {

namespace {

struct CodePointRange {
    unsigned long first;
    unsigned long last;
};

constexpr std::array<CodePointRange, 6> kForbiddenCodePoints = {{
    {0x0000, 0x001F},
    {0x007F, 0x009F},
    {0x061C, 0x061C},
    {0x200E, 0x200F},
    {0x2028, 0x202E},
    {0x2066, 0x2069},
}};

}  // namespace

bool isForbiddenCodePoint(const unsigned long codePoint)
{
    return std::any_of(kForbiddenCodePoints.begin(), kForbiddenCodePoints.end(),
        [codePoint](const CodePointRange& range) {
            return codePoint >= range.first && codePoint <= range.last;
        });
}

std::optional<std::size_t> plainCodePoints(const std::string_view text)
{
    const auto* cursor = reinterpret_cast<const unsigned char*>(text.data());
    std::size_t left = text.size();
    std::size_t count = 0;
    while (left > 0) {
        unsigned long codePoint = 0;
        const int length = UTF8_getc(cursor, static_cast<int>(left), &codePoint);
        if (length <= 0 || isForbiddenCodePoint(codePoint)) {
            return std::nullopt;
        }
        cursor += length;
        left -= static_cast<std::size_t>(length);
        ++count;
    }
    return count;
}

}  // namespace bazarish
