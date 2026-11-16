// Bazarish project (c) 2026
#include "Mentions.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <utility>

namespace bazarish::client {

namespace {

constexpr char kMentionSign = '@';
constexpr char kSpace = ' ';
constexpr char kSpaceInMention = '_';

constexpr unsigned char kContinuationMask = 0xC0;
constexpr unsigned char kContinuationBits = 0x80;
constexpr unsigned char kTwoByteMask = 0xE0;
constexpr unsigned char kTwoByteLead = 0xC0;
constexpr unsigned char kThreeByteMask = 0xF0;
constexpr unsigned char kThreeByteLead = 0xE0;
constexpr unsigned char kFourByteMask = 0xF8;
constexpr unsigned char kFourByteLead = 0xF0;
constexpr unsigned char kTwoBytePayload = 0x1F;
constexpr unsigned char kThreeBytePayload = 0x0F;
constexpr unsigned char kFourBytePayload = 0x07;
constexpr unsigned char kContinuationPayload = 0x3F;
constexpr int kContinuationShift = 6;
constexpr std::size_t kTwoBytes = 2;
constexpr std::size_t kThreeBytes = 3;
constexpr std::size_t kFourBytes = 4;

// Unicode White_Space.
constexpr char32_t kTabFirst = 0x09;
constexpr char32_t kCarriageReturn = 0x0D;
constexpr char32_t kNextLine = 0x85;
constexpr char32_t kNoBreakSpace = 0xA0;
constexpr char32_t kOghamSpace = 0x1680;
constexpr char32_t kEnQuad = 0x2000;
constexpr char32_t kHairSpace = 0x200A;
constexpr char32_t kLineSeparator = 0x2028;
constexpr char32_t kParagraphSeparator = 0x2029;
constexpr char32_t kNarrowNoBreakSpace = 0x202F;
constexpr char32_t kMathSpace = 0x205F;
constexpr char32_t kIdeographicSpace = 0x3000;

constexpr std::array<char32_t, 8> kOpeners{
    U'(', U'[', U'{', U'"', U'\'', 0xAB, 0x201C, 0x2018};
constexpr std::array<char32_t, 15> kClosers{U',', U'.', U'!', U'?', U':', U';', U')', U']',
    U'}', U'"', U'\'', 0xBB, 0x201D, 0x2019, 0x2026};

struct Point {
    char32_t value = 0;
    std::size_t bytes = 1;
};

Point pointAt(const std::string& text, const std::size_t at)
{
    const auto byte = [&text](const std::size_t index) {
        return static_cast<unsigned char>(text[index]);
    };
    const unsigned char lead = byte(at);
    std::size_t bytes = 1;
    char32_t value = lead;
    if ((lead & kTwoByteMask) == kTwoByteLead) {
        bytes = kTwoBytes;
        value = lead & kTwoBytePayload;
    } else if ((lead & kThreeByteMask) == kThreeByteLead) {
        bytes = kThreeBytes;
        value = lead & kThreeBytePayload;
    } else if ((lead & kFourByteMask) == kFourByteLead) {
        bytes = kFourBytes;
        value = lead & kFourBytePayload;
    }
    if (at + bytes > text.size()) {
        return {lead, 1};
    }
    for (std::size_t next = 1; next < bytes; ++next) {
        if ((byte(at + next) & kContinuationMask) != kContinuationBits) {
            return {lead, 1};
        }
        value = (value << kContinuationShift) | (byte(at + next) & kContinuationPayload);
    }
    return {value, bytes};
}

bool isWhiteSpace(const char32_t point)
{
    return (point >= kTabFirst && point <= kCarriageReturn) || point == U' ' || point == kNextLine
        || point == kNoBreakSpace || point == kOghamSpace
        || (point >= kEnQuad && point <= kHairSpace) || point == kLineSeparator
        || point == kParagraphSeparator || point == kNarrowNoBreakSpace || point == kMathSpace
        || point == kIdeographicSpace;
}

template <std::size_t N>
bool isOneOf(const std::array<char32_t, N>& set, const char32_t point)
{
    return std::find(set.begin(), set.end(), point) != set.end();
}

std::size_t lastPointStart(const std::string& text, const std::size_t end)
{
    std::size_t at = end - 1;
    while (at > 0
        && (static_cast<unsigned char>(text[at]) & kContinuationMask) == kContinuationBits) {
        --at;
    }
    return at;
}

}  // namespace

std::string mentionForm(const std::string& name)
{
    std::string form = name;
    std::replace(form.begin(), form.end(), kSpace, kSpaceInMention);
    return form;
}

std::vector<MentionSpan> findMentions(
    const std::string& text, const std::vector<std::string>& names)
{
    std::map<std::string, std::string> byForm;
    for (const std::string& name : names) {
        byForm.emplace(mentionForm(name), name);
    }
    std::vector<MentionSpan> spans;
    bool opens = true;
    std::size_t at = 0;
    while (at < text.size()) {
        const Point point = pointAt(text, at);
        if (point.value != static_cast<char32_t>(kMentionSign) || !opens) {
            opens = isWhiteSpace(point.value) || isOneOf(kOpeners, point.value);
            at += point.bytes;
            continue;
        }
        const std::size_t runStart = at + 1;
        std::size_t runEnd = runStart;
        while (runEnd < text.size()) {
            const Point next = pointAt(text, runEnd);
            if (isWhiteSpace(next.value)) {
                break;
            }
            runEnd += next.bytes;
        }
        std::size_t candidateEnd = runEnd;
        bool found = false;
        while (candidateEnd > runStart) {
            const auto named = byForm.find(text.substr(runStart, candidateEnd - runStart));
            if (named != byForm.end()) {
                spans.push_back({at, candidateEnd - at, named->second});
                found = true;
                break;
            }
            const std::size_t last = lastPointStart(text, candidateEnd);
            if (!isOneOf(kClosers, pointAt(text, last).value)) {
                break;
            }
            candidateEnd = last;
        }
        if (found) {
            at = candidateEnd;
            opens = false;
            continue;
        }
        opens = false;
        at = runStart;
    }
    return spans;
}

bool mentionsName(
    const std::string& text, const std::vector<std::string>& names, const std::string& name)
{
    if (name.empty()) {
        return false;
    }
    std::vector<std::string> all = names;
    all.push_back(name);
    const std::vector<MentionSpan> spans = findMentions(text, all);
    return std::any_of(spans.begin(), spans.end(),
        [&name](const MentionSpan& span) { return span.name == name; });
}

std::vector<std::string> mentionCandidates(const std::vector<std::string>& members,
    const std::string& own, const std::string& typed, const NameFold& fold,
    const std::size_t limit)
{
    const std::string wanted = fold(mentionForm(typed));
    std::vector<std::pair<std::string, std::string>> matching;
    for (const std::string& name : members) {
        if (name == own) {
            continue;
        }
        std::string folded = fold(mentionForm(name));
        if (folded.starts_with(wanted)) {
            matching.emplace_back(std::move(folded), name);
        }
    }
    std::sort(matching.begin(), matching.end());
    std::vector<std::string> chosen;
    for (std::size_t index = 0; index < matching.size() && index < limit; ++index) {
        chosen.push_back(matching[index].second);
    }
    return chosen;
}

}  // namespace bazarish::client
