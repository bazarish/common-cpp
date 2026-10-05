// Bazarish project (c) 2026
#pragma once

#include "bazarish/HttpServer.hpp"

#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish {

class WebAssets {
public:
    struct File {
        std::string body;
        std::string contentType;
        std::string etag;
    };

    explicit WebAssets(std::filesystem::path directory);

    const File& file(const std::string& name);

    std::string render(
        const std::string& templateName, const std::map<std::string, std::string>& values);

    std::vector<std::string> published() const;

private:
    std::filesystem::path directory_;
    mutable std::mutex mutex_;
    std::map<std::string, File> cache_;
};

http::Response serveWebAsset(const WebAssets::File& file, const http::Request& request);

std::string htmlEscape(const std::string& text);

}  // namespace bazarish
