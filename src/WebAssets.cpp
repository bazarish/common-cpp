// Bazarish project (c) 2026
#include "bazarish/WebAssets.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace bazarish {

namespace {

// What is served out of an asset directory, and as what. A file of any other
// type is not published: the directory holds a site, not a file share.
const std::map<std::string, std::string>& contentTypes()
{
    static const std::map<std::string, std::string> kTypes = {
        {".css", "text/css; charset=utf-8"},
        {".svg", "image/svg+xml"},
        {".png", "image/png"},
        {".ico", "image/x-icon"},
        {".js", "text/javascript; charset=utf-8"},
        {".woff2", "font/woff2"},
        {".txt", "text/plain; charset=utf-8"},
    };
    return kTypes;
}

// Templates are poured into pages by the service, so they are never served as
// files of their own.
const char* const kTemplateExtension = ".html";
const char* const kTemplateContentType = "text/html; charset=utf-8";

std::string readFile(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("web asset cannot be read: " + path.string());
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

void substitute(std::string& text, const std::string& token, const std::string& value)
{
    for (std::size_t at = text.find(token); at != std::string::npos;
         at = text.find(token, at + value.size())) {
        text.replace(at, token.size(), value);
    }
}

}  // namespace

WebAssets::WebAssets(std::filesystem::path directory)
    : directory_(std::move(directory))
{
    if (!std::filesystem::is_directory(directory_)) {
        throw std::runtime_error("web assets directory not found: " + directory_.string());
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    for (const std::filesystem::directory_entry& entry :
        std::filesystem::directory_iterator(directory_)) {
        if (entry.is_regular_file() && entry.path().extension() == kTemplateExtension) {
            cache_.emplace(entry.path().filename().string(),
                File{readFile(entry.path()), kTemplateContentType});
        }
    }
}

const WebAssets::File& WebAssets::file(const std::string& name)
{
    const std::filesystem::path asked(name);
    if (name.empty() || asked.filename() != asked) {
        throw std::runtime_error("web asset name is not a plain file name: " + name);
    }

    const std::lock_guard<std::mutex> lock(mutex_);
    const auto cached = cache_.find(name);
    if (cached != cache_.end()) {
        return cached->second;
    }
    const auto type = contentTypes().find(asked.extension().string());
    if (type == contentTypes().end()) {
        throw std::runtime_error("this type of file is not served: " + name);
    }
    return cache_.emplace(name, File{readFile(directory_ / name), type->second}).first->second;
}

std::string WebAssets::render(
    const std::string& templateName, const std::map<std::string, std::string>& values)
{
    std::string page = file(templateName).body;
    for (const auto& [name, value] : values) {
        substitute(page, "{{" + name + "}}", value);
    }
    return page;
}

std::vector<std::string> WebAssets::published() const
{
    std::vector<std::string> names;
    for (const std::filesystem::directory_entry& entry :
        std::filesystem::directory_iterator(directory_)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        if (contentTypes().count(entry.path().extension().string()) == 0) {
            continue;
        }
        names.push_back(entry.path().filename().string());
    }
    return names;
}

}  // namespace bazarish
