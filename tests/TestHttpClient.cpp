// Bazarish project (c) 2026
#include "bazarish/HttpClient.hpp"

#include "bazarish/HttpServer.hpp"

#include "TestUtil.hpp"

#include <chrono>
#include <string>
#include <thread>

using namespace bazarish;

namespace {

// Long enough that a loaded machine does not fail the test, short enough that a
// hung exchange does not hang the suite.
constexpr int kTimeoutSeconds = 10;
// Bigger than one write, so a streamed body has to come back in several chunks.
constexpr std::size_t kUploadBytes = 300 * 1024;

http::Server::Options serverOptions()
{
    http::Server::Options options;
    options.port = 0;  // the kernel picks one
    options.threads = 2;
    return options;
}

}  // namespace

int main()
{
    http::Server server(serverOptions());
    server.get("/hello", [](const http::Request& request) {
        http::Response answer;
        answer.contentType = "text/plain";
        answer.headers["X-Echo-Query"] = request.query("who");
        answer.body = "hello " + request.header("x-caller");
        return answer;
    });
    server.post("/echo", [](const http::Request& request) {
        http::Response answer;
        answer.contentType = request.header("content-type");
        answer.body = request.body;
        return answer;
    });
    server.put("/sink", [](const http::Request& request) {
        http::Response answer;
        answer.contentType = "text/plain";
        answer.body = std::to_string(request.body.size());
        return answer;
    });
    server.get("/slow", [](const http::Request&) {
        std::this_thread::sleep_for(std::chrono::seconds(kTimeoutSeconds));
        return http::Response{};
    });
    const int port = server.start();
    CHECK(port > 0);

    http::ClientOptions options;
    options.connectTimeout = std::chrono::seconds(kTimeoutSeconds);
    options.readTimeout = std::chrono::seconds(kTimeoutSeconds);
    options.writeTimeout = std::chrono::seconds(kTimeoutSeconds);

    // A GET carries its headers and query through, and the answer comes back
    // with its status, body and headers (keys lowercased).
    http::ClientRequest get;
    get.method = "GET";
    get.target = "/hello?who=world";
    get.headers["X-Caller"] = "test";
    const http::ClientResponse hello = http::request("127.0.0.1", port, get, options);
    CHECK(hello.error.empty());
    CHECK(hello.status == 200);
    CHECK(hello.body == "hello test");
    CHECK(hello.contentType == "text/plain");
    CHECK(hello.headers.at("x-echo-query") == "world");

    // A body goes out with its content type and comes back unchanged.
    http::ClientRequest post;
    post.method = "POST";
    post.target = "/echo";
    post.contentType = "application/json";
    post.body = "{\"a\":1}";
    const http::ClientResponse echoed = http::request("127.0.0.1", port, post, options);
    CHECK(echoed.status == 200);
    CHECK(echoed.body == post.body);
    CHECK(echoed.contentType == "application/json");

    // A streamed upload of a known length arrives whole, in as many chunks as it
    // takes.
    http::ClientRequest put;
    put.method = "PUT";
    put.target = "/sink";
    put.contentType = "application/octet-stream";
    std::size_t produced = 0;
    const http::BodyProvider provider = [&produced](char* const chunk, const std::size_t capacity) {
        const std::size_t want = std::min(capacity, kUploadBytes - produced);
        std::fill_n(chunk, want, 'x');
        produced += want;
        return want;
    };
    const http::ClientResponse stored
        = http::upload("127.0.0.1", port, put, kUploadBytes, provider, options);
    CHECK(stored.status == 200);
    CHECK(stored.body == std::to_string(kUploadBytes));
    CHECK(produced == kUploadBytes);

    // Nothing listening: a transport failure is status 0 with a reason, not an
    // exception, and it is not reported as a read timeout.
    const int kClosedPort = 9;  // discard/, never served here
    const http::ClientResponse refused = http::request("127.0.0.1", kClosedPort, get, options);
    CHECK(refused.status == 0);
    CHECK(!refused.error.empty());
    CHECK(!refused.readTimedOut);

    // A backend that never answers in time is a read timeout, which callers
    // report differently from an unreachable host.
    http::ClientOptions impatient = options;
    impatient.readTimeout = std::chrono::seconds(1);
    http::ClientRequest slow;
    slow.method = "GET";
    slow.target = "/slow";
    const http::ClientResponse late = http::request("127.0.0.1", port, slow, impatient);
    CHECK(late.status == 0);
    CHECK(late.readTimedOut);

    server.stop();
    std::printf("TestHttpClient: all checks passed\n");
    return 0;
}
