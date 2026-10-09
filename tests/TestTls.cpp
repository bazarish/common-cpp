// Bazarish project (c) 2026
#include "bazarish/Tls.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/HttpClient.hpp"
#include "bazarish/HttpServer.hpp"
#include "TestUtil.hpp"

#include <cstdio>
#include <filesystem>

namespace fs = std::filesystem;
using namespace bazarish;

namespace {

http::ClientResponse ask(const int port, const http::ClientOptions& options)
{
    http::ClientRequest request;
    request.method = "GET";
    request.target = "/healthz";
    return http::request("127.0.0.1", port, request, options);
}

http::ClientOptions pinned(const std::string& pin)
{
    http::ClientOptions options;
    options.tls = true;
    options.pin = pin;
    options.connectTimeout = std::chrono::seconds(5);
    options.readTimeout = std::chrono::seconds(5);
    return options;
}

}  // namespace

int main()
{
    const fs::path root = fs::temp_directory_path() / ("bazarish-tls-" + toHex(randomBytes(8)));
    fs::create_directories(root);

    const tls::Credential made = tls::selfSigned(root);
    CHECK(fs::exists(made.certificate));
    CHECK(fs::exists(made.key));
    CHECK(made.pin.size() == 64);
    CHECK(made.pin == tls::pinOfCertificate(made.certificate));

    const tls::Credential again = tls::selfSigned(root);
    CHECK(again.pin == made.pin);
    CHECK(again.certificate == made.certificate);

    const tls::Credential caller = tls::selfSigned(root / "caller");
    CHECK(caller.pin != made.pin);

    CHECK_THROWS(tls::pinOfCertificate(made.key));

    {
        http::Server::Options options;
        options.port = 0;
        options.threads = 1;
        options.certificate = made.certificate.string();
        options.key = made.key.string();
        http::Server server(options);
        server.get("/healthz", [](const http::Request&) {
            return http::Response{200, "application/json", {}, R"({"ok":true})"};
        });
        const int port = server.start();

        CHECK(ask(port, pinned(made.pin)).status == 200);
        CHECK(ask(port, pinned(caller.pin)).status == 0);

        http::ClientOptions plain;
        plain.connectTimeout = std::chrono::seconds(5);
        plain.readTimeout = std::chrono::seconds(5);
        CHECK(ask(port, plain).status == 0);
        server.stop();
    }

    {
        http::Server::Options options;
        options.port = 0;
        options.threads = 1;
        options.certificate = made.certificate.string();
        options.key = made.key.string();
        options.clientPins = {caller.pin};
        http::Server server(options);
        server.get("/healthz", [](const http::Request&) {
            return http::Response{200, "application/json", {}, R"({"ok":true})"};
        });
        const int port = server.start();

        http::ClientOptions named = pinned(made.pin);
        named.certificate = caller.certificate.string();
        named.key = caller.key.string();
        CHECK(ask(port, named).status == 200);

        CHECK(ask(port, pinned(made.pin)).status == 0);

        const tls::Credential stranger = tls::selfSigned(root / "stranger");
        http::ClientOptions unlisted = pinned(made.pin);
        unlisted.certificate = stranger.certificate.string();
        unlisted.key = stranger.key.string();
        CHECK(ask(port, unlisted).status == 0);
        server.stop();
    }

    fs::remove_all(root);
    std::printf("TestTls: all checks passed\n");
    return 0;
}
