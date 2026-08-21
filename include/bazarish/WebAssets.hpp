// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish {

// A directory of web files served by a daemon: HTML templates it fills in, plus
// the stylesheets, scripts, images and fonts a browser asks for by name. They sit
// on disk beside the binary instead of inside it, so an operator owns what the
// pages say and how they look without rebuilding anything.
//
// Each file is read once and answered from memory afterwards, which also means an
// edit takes effect on restart.
class WebAssets {
public:
    struct File {
        std::string body;
        std::string contentType;
    };

    // Loads every template at once: a service that cannot draw its own pages must
    // say so at start, not on the first visitor.
    explicit WebAssets(std::filesystem::path directory);

    // A file by its plain name, read on first use. Throws when the name is not a
    // plain file name, when its type is not one that is served, or when the file
    // cannot be read.
    const File& file(const std::string& name);

    // A template with its {{placeholders}} filled in from values; a placeholder
    // with no value is left as it stands, so a typo in a template shows up as
    // itself instead of vanishing.
    std::string render(
        const std::string& templateName, const std::map<std::string, std::string>& values);

    // The files published: everything in the directory a browser may ask for by
    // name (templates are filled in by the service, not served).
    std::vector<std::string> published() const;

private:
    std::filesystem::path directory_;
    mutable std::mutex mutex_;
    std::map<std::string, File> cache_;
};

}  // namespace bazarish
