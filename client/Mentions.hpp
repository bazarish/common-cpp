// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace bazarish::client {

inline constexpr std::size_t kMaxMentionCandidates = 5;

struct MentionSpan {
    // UTF-8 bytes into the text; the span starts at the '@'.
    std::size_t offset = 0;
    std::size_t length = 0;
    std::string name;
};

using NameFold = std::function<std::string(const std::string&)>;

std::string mentionForm(const std::string& name);
// docs-main Groups.md, Mentions.
std::vector<MentionSpan> findMentions(
    const std::string& text, const std::vector<std::string>& names);
bool mentionsName(const std::string& text, const std::vector<std::string>& names,
    const std::string& name);
// Names, not mention forms, in the order of their folded spelling.
std::vector<std::string> mentionCandidates(const std::vector<std::string>& members,
    const std::string& own, const std::string& typed, const NameFold& fold,
    std::size_t limit = kMaxMentionCandidates);

}  // namespace bazarish::client
