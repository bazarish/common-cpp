// Bazarish project (c) 2026
#include "bazarish/HttpClient.hpp"

#include "bazarish/Bytes.hpp"

#include "bazarish/HttpServer.hpp"

#include "TestUtil.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

using namespace bazarish;

namespace {

constexpr int kTimeoutSeconds = 10;
constexpr std::size_t kUploadBytes = 300 * 1024;

std::string readHead(boost::asio::ip::tcp::socket& peer)
{
    std::string head;
    char byte = 0;
    boost::system::error_code error;
    while (head.find("\r\n\r\n") == std::string::npos) {
        const std::size_t got = peer.read_some(boost::asio::buffer(&byte, 1), error);
        if (error || got == 0) {
            return {};
        }
        head.push_back(byte);
    }
    return head;
}

std::string rawResponse(const std::string& head, const std::string& body)
{
    return head + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

http::Server::Options serverOptions()
{
    http::Server::Options options;
    options.port = 0;
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
        answer.body = request.param("blob") + "|" + request.param("who");
        return answer;
    });
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
        CHECK(cookieOf("session=a.b.c; other=1", "session") == "a.b.c");
        CHECK(cookieOf("", "session").empty());
    }

    http::ClientRequest post;
    post.method = "POST";
    post.target = "/echo";
    post.contentType = "application/json";
    post.body = "{\"a\":1}";
    const http::ClientResponse echoed = http::request("127.0.0.1", port, post, options);
    CHECK(echoed.status == 200);
    CHECK(echoed.body == post.body);
    CHECK(echoed.contentType == "application/json");

    http::ClientRequest form;
    form.method = "POST";
    form.target = "/form?who=a%2Fb";
    form.contentType = "application/x-www-form-urlencoded";
    form.body = "blob=aGVsbG8%2Bd29ybGQ%3D&other=1";
    const http::ClientResponse posted = http::request("127.0.0.1", port, form, options);
    CHECK(posted.status == 200);
    CHECK(posted.body == "aGVsbG8+d29ybGQ=|a/b");

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

    http::ClientOptions vaultOptions = options;
    vaultOptions.digestUser = "walletuser";
    vaultOptions.digestPassword = "walletpass";
    http::ClientRequest vault;
    vault.method = "GET";
    vault.target = "/vault";
    const http::ClientResponse authorized = http::request("127.0.0.1", port, vault, vaultOptions);
    CHECK(authorized.status == 200);
    CHECK(authorized.body == "welcome");

    const http::ClientResponse challenged = http::request("127.0.0.1", port, vault, options);
    CHECK(challenged.status == 401);
    CHECK(challenged.headers.count("www-authenticate") == 1);

    const int kClosedPort = 9;
    const http::ClientResponse refused = http::request("127.0.0.1", kClosedPort, get, options);
    CHECK(refused.status == 0);
    CHECK(!refused.error.empty());
    CHECK(!refused.readTimedOut);

    http::ClientOptions impatient = options;
    impatient.readTimeout = std::chrono::seconds(1);
    http::ClientRequest slow;
    slow.method = "GET";
    slow.target = "/slow";
    const http::ClientResponse late = http::request("127.0.0.1", port, slow, impatient);
    CHECK(late.status == 0);
    CHECK(late.readTimedOut);

    server.stop();
    {
        std::string sawAuthorization;
        http::Server::Options options;
        options.port = 0;
        http::Server server(options);
        server.get("/basic", [&sawAuthorization](const http::Request& request) {
            const auto found = request.headers.find("authorization");
            sawAuthorization = found == request.headers.end() ? std::string() : found->second;
            http::Response response;
            response.status = sawAuthorization.empty() ? 401 : 200;
            response.body = "{}";
            return response;
        });
        const int port = server.start();
        CHECK(port > 0);

        http::ClientRequest ask;
        ask.method = "GET";
        ask.target = "/basic";
        http::ClientOptions withBasic;
        withBasic.basicUser = "rpcuser";
        withBasic.basicPassword = "s3cret";
        const http::ClientResponse answered = http::request("127.0.0.1", port, ask, withBasic);
        CHECK(answered.status == 200);
        const std::string pair = "rpcuser:s3cret";
        CHECK(sawAuthorization
            == "Basic " + bazarish::toBase64(bazarish::Bytes(pair.begin(), pair.end())));

        sawAuthorization.clear();
        const http::ClientResponse bare = http::request("127.0.0.1", port, ask, {});
        CHECK(bare.status == 401);
        CHECK(sawAuthorization.empty());
        server.stop();
    }

    {
        using boost::asio::ip::tcp;
        boost::asio::io_context loop;
        tcp::acceptor door(loop, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
        const int port = door.local_endpoint().port();
        std::atomic<int> accepted{0};
        std::thread serving([&door, &accepted] {
            tcp::socket peer = door.accept();
            ++accepted;
            door.close();
            const std::string nonce = "boundtothisone";
            for (;;) {
                const std::string head = readHead(peer);
                if (head.empty()) {
                    return;
                }
                const bool carried = head.find("Authorization: Digest") != std::string::npos
                    && head.find("nonce=\"" + nonce + "\"") != std::string::npos;
                const std::string answer = carried
                    ? rawResponse("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n", "welcome")
                    : rawResponse("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest "
                                  "realm=\"monero-rpc\", nonce=\"" + nonce + "\", qop=\"auth\"\r\n",
                        "who goes there");
                boost::asio::write(peer, boost::asio::buffer(answer));
                if (carried) {
                    return;
                }
            }
        });

        http::ClientOptions bound;
        bound.digestUser = "walletuser";
        bound.digestPassword = "walletpass";
        bound.connectTimeout = std::chrono::seconds(kTimeoutSeconds);
        bound.readTimeout = std::chrono::seconds(kTimeoutSeconds);
        http::ClientRequest ask;
        ask.method = "GET";
        ask.target = "/json_rpc";
        const http::ClientResponse welcomed = http::request("127.0.0.1", port, ask, bound);
        serving.join();
        CHECK(welcomed.status == 200);
        CHECK(welcomed.body == "welcome");
        CHECK(accepted == 1);
    }

    std::printf("TestHttpClient: all checks passed\n");
    return 0;
}
