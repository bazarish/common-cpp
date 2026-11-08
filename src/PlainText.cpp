// Bazarish project (c) 2026
#include "bazarish/PlainText.hpp"

#include <openssl/asn1.h>

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

std::string safeFileName(const std::string_view offered)
{
    const std::size_t lastSeparator = offered.find_last_of(kPathSeparators);
    const std::string_view last
        = lastSeparator == std::string_view::npos ? offered : offered.substr(lastSeparator + 1);

    std::string name;
    const auto* cursor = reinterpret_cast<const unsigned char*>(last.data());
    std::size_t left = last.size();
    while (left > 0) {
        unsigned long codePoint = 0;
        const int length = UTF8_getc(cursor, static_cast<int>(left), &codePoint);
        if (length <= 0) {
            ++cursor;
            --left;
            continue;
        }
        if (!isForbiddenCodePoint(codePoint)) {
            const char* const at = reinterpret_cast<const char*>(cursor);
            name.append(at, static_cast<std::size_t>(length));
        }
        cursor += length;
        left -= static_cast<std::size_t>(length);
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
