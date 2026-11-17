// Bazarish project (c) 2026
#include "bazarish/PlainText.hpp"

#include <algorithm>
#include <array>
#include <cctype>

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

constexpr std::string_view kPathSeparators = "/\\";
constexpr std::string_view kNotInWindowsNames = "<>:\"|?*";
constexpr std::string_view kTrimmedTail = ". ";
constexpr char kReplacement = '_';
constexpr char kExtensionMark = '.';
constexpr std::size_t kLongestKeptExtension = 16;
constexpr char kUnnamed[] = "file";
constexpr std::array<std::string_view, 4> kWindowsDevices = {"CON", "PRN", "AUX", "NUL"};
constexpr std::array<std::string_view, 2> kNumberedWindowsDevices = {"COM", "LPT"};

// RFC 3629: a continuation byte is 10xxxxxx.
constexpr unsigned char kUtf8ContinuationMask = 0xC0;
constexpr unsigned char kUtf8ContinuationBits = 0x80;
constexpr unsigned char kUtf8PayloadMask = 0x3F;
constexpr unsigned kUtf8PayloadBits = 6;
constexpr unsigned long kMaxCodePoint = 0x10FFFF;
constexpr unsigned long kFirstSurrogate = 0xD800;
constexpr unsigned long kLastSurrogate = 0xDFFF;

struct Utf8Lead {
    unsigned char mask;
    unsigned char bits;
    std::size_t length;
    unsigned long smallest;
};

constexpr std::array<Utf8Lead, 4> kUtf8Leads = {{
    {0x80, 0x00, 1, 0x0},
    {0xE0, 0xC0, 2, 0x80},
    {0xF0, 0xE0, 3, 0x800},
    {0xF8, 0xF0, 4, 0x10000},
}};

bool isUtf8Continuation(const char c)
{
    return (static_cast<unsigned char>(c) & kUtf8ContinuationMask) == kUtf8ContinuationBits;
}

std::string upper(std::string_view text)
{
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return out;
}

bool isWindowsDevice(std::string_view name)
{
    const std::string stem = upper(name.substr(0, name.find(kExtensionMark)));
    if (std::find(kWindowsDevices.begin(), kWindowsDevices.end(), stem) != kWindowsDevices.end()) {
        return true;
    }
    return std::any_of(kNumberedWindowsDevices.begin(), kNumberedWindowsDevices.end(),
        [&stem](const std::string_view prefix) {
            return stem.size() == prefix.size() + 1 && stem.starts_with(prefix)
                && std::isdigit(static_cast<unsigned char>(stem.back())) && stem.back() != '0';
        });
}

std::string cutToBytes(const std::string& text, std::size_t limit)
{
    if (text.size() <= limit) {
        return text;
    }
    while (limit > 0 && isUtf8Continuation(text[limit])) {
        --limit;
    }
    return text.substr(0, limit);
}

}  // namespace

bool isForbiddenCodePoint(const unsigned long codePoint)
{
    return std::any_of(kForbiddenCodePoints.begin(), kForbiddenCodePoints.end(),
        [codePoint](const CodePointRange& range) {
            return codePoint >= range.first && codePoint <= range.last;
        });
}

std::optional<Utf8CodePoint> nextUtf8CodePoint(const std::string_view text)
{
    if (text.empty()) {
        return std::nullopt;
    }
    const auto first = static_cast<unsigned char>(text.front());
    const auto lead = std::find_if(kUtf8Leads.begin(), kUtf8Leads.end(),
        [first](const Utf8Lead& candidate) { return (first & candidate.mask) == candidate.bits; });
    if (lead == kUtf8Leads.end() || text.size() < lead->length) {
        return std::nullopt;
    }
    unsigned long value = first & static_cast<unsigned char>(~lead->mask);
    for (std::size_t i = 1; i < lead->length; ++i) {
        if (!isUtf8Continuation(text[i])) {
            return std::nullopt;
        }
        value = (value << kUtf8PayloadBits) | (static_cast<unsigned char>(text[i]) & kUtf8PayloadMask);
    }
    if (value < lead->smallest || value > kMaxCodePoint
        || (value >= kFirstSurrogate && value <= kLastSurrogate)) {
        return std::nullopt;
    }
    return Utf8CodePoint{value, lead->length};
}

std::optional<std::size_t> plainCodePoints(std::string_view text)
{
    std::size_t count = 0;
    while (!text.empty()) {
        const std::optional<Utf8CodePoint> codePoint = nextUtf8CodePoint(text);
        if (!codePoint || isForbiddenCodePoint(codePoint->value)) {
            return std::nullopt;
        }
        text.remove_prefix(codePoint->length);
        ++count;
    }
    return count;
}

std::string safeFileName(const std::string_view offered)
{
    const std::size_t lastSeparator = offered.find_last_of(kPathSeparators);
    const std::string_view last
        = lastSeparator == std::string_view::npos ? offered : offered.substr(lastSeparator + 1);

    std::string name;
    std::string_view left = last;
    while (!left.empty()) {
        const std::optional<Utf8CodePoint> codePoint = nextUtf8CodePoint(left);
        if (!codePoint) {
            left.remove_prefix(1);
            continue;
        }
        if (!isForbiddenCodePoint(codePoint->value)) {
            name.append(left.substr(0, codePoint->length));
        }
        left.remove_prefix(codePoint->length);
    }
    std::replace_if(name.begin(), name.end(),
        [](const char c) { return kNotInWindowsNames.find(c) != std::string_view::npos; },
        kReplacement);
    name.erase(name.find_last_not_of(kTrimmedTail) + 1);
    if (name.empty()) {
        return kUnnamed;
    }
    if (isWindowsDevice(name)) {
        name.insert(name.begin(), kReplacement);
    }
    if (name.size() > kMaxFileNameBytes) {
        const std::size_t dot = name.rfind(kExtensionMark);
        const std::string extension = dot != std::string::npos && dot > 0
                && name.size() - dot <= kLongestKeptExtension
            ? name.substr(dot)
            : std::string();
        name = cutToBytes(name.substr(0, name.size() - extension.size()),
                   kMaxFileNameBytes - extension.size())
            + extension;
    }
    return name;
}

std::string asciiLower(std::string text)
{
    for (char& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return text;
}

}  // namespace bazarish
