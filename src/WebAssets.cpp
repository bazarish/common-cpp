// Bazarish project (c) 2026
#include "bazarish/WebAssets.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

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

// HTTP status for a caller that already holds the body it asked for.
constexpr int kNotModified = 304;

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

WebAssets::File loadFile(const std::filesystem::path& path, const std::string& contentType)
{
    std::string body = readFile(path);
    const Bytes bytes(body.begin(), body.end());
    // The tag is the content itself, hashed: two servers handed the same file
    // answer with the same tag, and a redeploy that does not change a file does
    // not invalidate anybody's copy of it.
    std::string etag = "\"" + toHex(sha256(bytes)) + "\"";
    return {std::move(body), contentType, std::move(etag)};
}

std::string trimmed(const std::string& text)
{
    const std::size_t first = text.find_first_not_of(" \t");
    if (first == std::string::npos) {
        return {};
    }
    return text.substr(first, text.find_last_not_of(" \t") - first + 1);
}

// Whether an If-None-Match header names the tag we hold. The header is a list,
// "*" stands for any representation, and a weak tag (W/"...") is compared as it
// is written: these files are served whole, so they have no weaker form for the
// distinction to be about.
bool namesEtag(const std::string& header, const std::string& etag)
{
    std::size_t at = 0;
    while (at <= header.size()) {
        const std::size_t comma = header.find(',', at);
        std::string tag = trimmed(
            header.substr(at, comma == std::string::npos ? comma : comma - at));
        if (tag.rfind("W/", 0) == 0) {
            tag = tag.substr(2);
        }
        if (tag == "*" || tag == etag) {
            return true;
        }
        if (comma == std::string::npos) {
            break;
        }
        at = comma + 1;
    }
    return false;
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
                loadFile(entry.path(), kTemplateContentType));
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
    return cache_.emplace(name, loadFile(directory_ / name, type->second)).first->second;
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

http::Response serveWebAsset(const WebAssets::File& file, const http::Request& request)
{
    http::Response response;
    response.contentType = file.contentType;
    response.headers["ETag"] = file.etag;
    // Ask every time. These files are read once and change only when the operator
    // edits them and restarts the service, which is exactly what a browser cannot
    // know: left to its own heuristics it would go on drawing the old page for as
    // long as it liked. Revalidating costs a header, because the answer is a 304.
    response.headers["Cache-Control"] = "no-cache";
    if (namesEtag(request.header("if-none-match"), file.etag)) {
        response.status = kNotModified;
        return response;
    }
    response.body = file.body;
    return response;
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
