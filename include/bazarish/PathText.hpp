// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace bazarish {

// Paths written as text are UTF-8; on Windows a std::string path is read in the ANSI code page.
inline std::filesystem::path pathFromUtf8(const std::string_view text)
{
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}

inline std::string utf8OfPath(const std::filesystem::path& path)
{
    const std::u8string text = path.u8string();
    return std::string(text.begin(), text.end());
}

}  // namespace bazarish
