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
    server.post("/form", [](const http::Request& request) {
        http::Response answer;
        answer.contentType = "text/plain";
        // A form field and a query value read the same way, both decoded.
        answer.body = request.param("blob") + "|" + request.param("who");
        return answer;
    });
    // Reads back one cookie by name, so a test can see what the server got.
    server.get("/cookie", [](const http::Request& request) {
        http::Response answer;
        answer.contentType = "text/plain";
        answer.body = request.cookie(request.query("name"));
        return answer;
    });
    server.put("/sink", [](const http::Request& request) {
        http::Response answer;
        answer.contentType = "text/plain";
        answer.body = std::to_string(request.body.size());
        return answer;
    });
    // A backend that wants HTTP Digest credentials: it 401s with a challenge and
    // then checks the answer the client computes from it.
    server.get("/vault", [](const http::Request& request) {
        http::Response answer;
        answer.contentType = "text/plain";
        const std::string authorization = request.header("authorization");
        if (authorization.rfind("Digest ", 0) != 0) {
            answer.status = 401;
            answer.headers["WWW-Authenticate"]
                = R"(Digest realm="monero-wallet-rpc", nonce="abc123", qop="auth")";
            answer.body = "who goes there";
            return answer;
        }
        // The response is what proves the password without sending it; the rest
        // of the header only says how it was computed.
        const bool named = authorization.find(R"(username="walletuser")") != std::string::npos;
        const bool answered = authorization.find(R"(response=")") != std::string::npos;
        const bool counted = authorization.find("nc=00000001") != std::string::npos;
        answer.body = named && answered && counted ? "welcome" : "no";
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

    // Cookies are matched by whole name. Two services on one host share a
    // cookie jar, and "adminsession" used to answer for "session" - the portal
    // then read the panel's token, found it invalid, and showed the sign-in
    // page again with nothing wrong on it.
    {
        const auto cookieOf = [port, &options](const std::string& jar, const std::string& name) {
            http::ClientRequest ask;
            ask.method = "GET";
            ask.target = "/cookie?name=" + name;
            ask.headers["Cookie"] = jar;
            return http::request("127.0.0.1", port, ask, options).body;
        };
        CHECK(cookieOf("session=portal", "session") == "portal");
        CHECK(cookieOf("adminsession=panel; session=portal", "session") == "portal");
        CHECK(cookieOf("adminsession=panel", "session").empty());
        CHECK(cookieOf("adminsession=panel; session=portal", "adminsession") == "panel");
        // Values keep whatever they are made of; only the name is parsed.
        CHECK(cookieOf("session=a.b.c; other=1", "session") == "a.b.c");
        CHECK(cookieOf("", "session").empty());
    }

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

    // An HTML form posts its fields as an urlencoded body: they arrive decoded,
    // "+" included, and a query value on the same request is read the same way.
    http::ClientRequest form;
    form.method = "POST";
    form.target = "/form?who=a%2Fb";
    form.contentType = "application/x-www-form-urlencoded";
    form.body = "blob=aGVsbG8%2Bd29ybGQ%3D&other=1";
    const http::ClientResponse posted = http::request("127.0.0.1", port, form, options);
    CHECK(posted.status == 200);
    CHECK(posted.body == "aGVsbG8+d29ybGQ=|a/b");

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

    // A digest challenge is answered on a second attempt, with the credentials
    // computed from what the server asked for.
    http::ClientOptions vaultOptions = options;
    vaultOptions.digestUser = "walletuser";
    vaultOptions.digestPassword = "walletpass";
    http::ClientRequest vault;
    vault.method = "GET";
    vault.target = "/vault";
    const http::ClientResponse authorized = http::request("127.0.0.1", port, vault, vaultOptions);
    CHECK(authorized.status == 200);
    CHECK(authorized.body == "welcome");

    // Without credentials the challenge reaches the caller as it stands.
    const http::ClientResponse challenged = http::request("127.0.0.1", port, vault, options);
    CHECK(challenged.status == 401);
    CHECK(challenged.headers.count("www-authenticate") == 1);

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
