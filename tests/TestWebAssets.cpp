// Bazarish project (c) 2026
#include "bazarish/WebAssets.hpp"

#include "TestUtil.hpp"

#include <filesystem>
#include <fstream>
#include <string>

using namespace bazarish;

namespace {

constexpr int kOk = 200;
constexpr int kNotModified = 304;

void write(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream stream(path, std::ios::binary);
    stream << text;
    if (!stream) {
        throw std::runtime_error("cannot write " + path.string());
    }
}

http::Request asking(const std::string& ifNoneMatch)
{
    http::Request request;
    request.method = "GET";
    if (!ifNoneMatch.empty()) {
        request.headers["if-none-match"] = ifNoneMatch;
    }
    return request;
}

}  // namespace

int main()
{
    const std::filesystem::path dir
        = std::filesystem::temp_directory_path() / "bazarish-web-assets-test";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    write(dir / "page.html", "<p>{{note}}</p>");
    write(dir / "style.css", "body { color: #d7dbd8; }");

    WebAssets assets(dir);
    const std::string css = assets.file("style.css").body;
    const std::string etag = assets.file("style.css").etag;
    CHECK(css == "body { color: #d7dbd8; }");
    CHECK(etag.size() > 2 && etag.front() == '"' && etag.back() == '"');

    // Read once: the file on disk changes and what is served does not, which is
    // why editing one of these is followed by a restart.
    write(dir / "style.css", "body { color: #39ff14; }");
    CHECK(assets.file("style.css").body == css);
    CHECK(assets.file("style.css").etag == etag);

    // A caller with no tag is handed the file and the tag for it.
    const http::Response full = serveWebAsset(assets.file("style.css"), asking(""));
    CHECK(full.status == kOk);
    CHECK(full.body == css);
    CHECK(full.contentType == "text/css; charset=utf-8");
    CHECK(full.headers.at("ETag") == etag);

    // A caller that already holds the body downloads nothing, and still learns
    // the tag is current.
    const http::Response cached = serveWebAsset(assets.file("style.css"), asking(etag));
    CHECK(cached.status == kNotModified);
    CHECK(cached.body.empty());
    CHECK(cached.headers.at("ETag") == etag);

    // A list, a weak tag and "*" all name what we hold; another tag does not.
    CHECK(serveWebAsset(assets.file("style.css"), asking("\"other\", " + etag)).status
        == kNotModified);
    CHECK(serveWebAsset(assets.file("style.css"), asking("W/" + etag)).status == kNotModified);
    CHECK(serveWebAsset(assets.file("style.css"), asking("*")).status == kNotModified);
    CHECK(serveWebAsset(assets.file("style.css"), asking("\"other\"")).status == kOk);

    // The tag is the content: the same bytes under another name carry the same
    // one, different bytes do not.
    write(dir / "copy.css", css);
    CHECK(assets.file("copy.css").etag == etag);
    CHECK(assets.file("page.html").etag != etag);

    // Templates are loaded at construction and poured into pages, not served.
    CHECK(assets.render("page.html", {{"note", "hello"}}) == "<p>hello</p>");
    CHECK_THROWS(assets.file("secrets.json"));

    std::filesystem::remove_all(dir);
    std::printf("TestWebAssets: all checks passed\n");
    return 0;
}
