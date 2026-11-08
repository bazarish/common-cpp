// Bazarish project (c) 2026
#include "bazarish/HttpServer.hpp"

#include "TestUtil.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>

#include <atomic>
#include <chrono>
#include <map>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;

namespace {

constexpr int kOk = 200;
constexpr int kForbidden = 403;
constexpr int kMissing = 404;
constexpr int kMisdirected = 421;
constexpr int kUriTooLong = 414;
constexpr std::size_t kHostilePathBytes = 60000;
constexpr int kStopRounds = 50;
constexpr std::chrono::milliseconds kParkPoll{10};
constexpr std::chrono::seconds kParkWithin{10};

struct Answer {
    int status = 0;
    std::map<std::string, std::string> headers;
};

Answer ask(http::Server& server, const std::string& method, const std::string& path,
    const std::string& fetchSite = {})
{
    http::Request request;
    request.method = method;
    request.path = path;
    request.target = path;
    if (!fetchSite.empty()) {
        request.headers["sec-fetch-site"] = fetchSite;
    }
    Answer answer;
    server.dispatch(request, [&answer](http::Response response) {
        answer.status = response.status;
        answer.headers = response.headers;
    });
    return answer;
}

http::Handler echo(std::vector<std::string>& into)
{
    return [&into](const http::Request& request) {
        into = request.captures;
        return http::Response{};
    };
}

}  // namespace

int main()
{
    http::Server server(http::Server::Options{});
    std::vector<std::string> captured;
    server.get("/healthz", echo(captured));
    server.get("/v1/transfers/{hex}", echo(captured));
    server.post("/ui/accounts/{hex}/chats/{b32}/clear", echo(captured));
    server.get("/lang/{lang}", echo(captured));
    server.post("/v1/op/{op}", echo(captured));
    server.get("/assets/{asset}", echo(captured));
    server.del("/v1/messaging/clients/{id}", echo(captured));
    server.get("/v1/alias/{alias}", echo(captured));
    server.del("/tokens/{segment}", echo(captured));
    server.route("PUT", "*", echo(captured));

    CHECK(ask(server, "GET", "/healthz").status == kOk);
    CHECK(captured.empty());
    CHECK(ask(server, "GET", "/healthz/").status == kMissing);
    CHECK(ask(server, "POST", "/healthz").status == kMissing);

    CHECK(ask(server, "GET", "/v1/transfers/0a9f").status == kOk);
    CHECK(captured == std::vector<std::string>{"0a9f"});
    CHECK(ask(server, "GET", "/v1/transfers/0A9F").status == kMissing);
    CHECK(ask(server, "GET", "/v1/transfers/").status == kMissing);
    CHECK(ask(server, "GET", "/v1/transfers/ab/cd").status == kMissing);

    CHECK(ask(server, "POST", "/ui/accounts/beef/chats/abc27/clear").status == kOk);
    CHECK((captured == std::vector<std::string>{"beef", "abc27"}));
    CHECK(ask(server, "POST", "/ui/accounts/beef/chats/abc18/clear").status == kMissing);

    CHECK(ask(server, "GET", "/lang/pt-br").status == kOk);
    CHECK(ask(server, "POST", "/v1/op/alias.renew").status == kOk);
    CHECK(captured == std::vector<std::string>{"alias.renew"});
    CHECK(ask(server, "GET", "/assets/Roboto_Mono-1.woff2").status == kOk);
    CHECK(ask(server, "GET", "/assets/a/b").status == kMissing);
    CHECK(ask(server, "DELETE", "/v1/messaging/clients/desk_1-a").status == kOk);
    CHECK(ask(server, "GET", "/v1/alias/name-word").status == kOk);
    CHECK(captured == std::vector<std::string>{"name-word"});
    CHECK(ask(server, "DELETE", "/tokens/A~b+c").status == kOk);
    CHECK(ask(server, "GET", "/healthz").headers.count("X-Frame-Options") == 0);
    {
        http::Server::Options framedOptions;
        framedOptions.denyFraming = true;
        http::Server page(framedOptions);
        std::vector<std::string> seen;
        page.route(http::kAnyMethod, "*", echo(seen));
        const Answer odd = ask(page, "OPTIONS", "/anything");
        CHECK(odd.status == kOk);
        CHECK(odd.headers.at("X-Frame-Options") == "DENY");
        CHECK(odd.headers.at("Content-Security-Policy") == "frame-ancestors 'none'");
    }

    CHECK(ask(server, "PUT", "/any/path?x=1").status == kOk);
    CHECK(captured == std::vector<std::string>{"/any/path?x=1"});

    const std::size_t longest = http::Server::Options{}.maxTargetBytes;
    const std::string longPath = "/" + std::string(longest - 1, 'z');
    CHECK(ask(server, "PUT", longPath).status == kOk);
    CHECK(captured.at(0) == longPath);
    CHECK(ask(server, "GET", "/lang/" + std::string(longest - 6, 'z')).status == kOk);
    CHECK(ask(server, "GET", "/v1/transfers/" + std::string(longest - 14, 'z')).status == kMissing);

    captured.clear();
    const std::string hostile(kHostilePathBytes, 'z');
    CHECK(ask(server, "PUT", "/" + hostile).status == kUriTooLong);
    CHECK(ask(server, "PUT", longPath + "z").status == kUriTooLong);
    CHECK(captured.empty());

    CHECK_THROWS(server.get("/v1/{nonsense}", echo(captured)));
    CHECK_THROWS(server.get("/price/(.+)", echo(captured)));

    CHECK(ask(server, "POST", "/v1/op/alias.renew", "cross-site").status == kForbidden);
    CHECK(ask(server, "POST", "/v1/op/alias.renew", "same-site").status == kForbidden);
    CHECK(ask(server, "DELETE", "/tokens/x", "cross-site").status == kForbidden);
    CHECK(ask(server, "POST", "/v1/op/alias.renew", "same-origin").status == kOk);
    CHECK(ask(server, "GET", "/healthz", "cross-site").status == kOk);

    http::Server::Options pinned;
    pinned.hosts = {"127.0.0.1", "Bot.Example", "[::1]"};
    http::Server named(pinned);
    named.get("/ui/state", echo(captured));
    const auto askHost = [&named](const std::string& host) {
        http::Request request;
        request.method = "GET";
        request.path = "/ui/state";
        request.target = request.path;
        request.headers["host"] = host;
        int status = 0;
        named.dispatch(request, [&status](http::Response response) { status = response.status; });
        return status;
    };
    CHECK(askHost("127.0.0.1:8440") == kOk);
    CHECK(askHost("127.0.0.1") == kOk);
    CHECK(askHost("bot.example") == kOk);
    CHECK(askHost("[::1]:8440") == kOk);
    CHECK(askHost("rebound.example") == kMisdirected);
    CHECK(askHost("") == kMisdirected);

    http::Request tossed;
    tossed.headers["cookie"] = "session=theirs; lang=en; session=mine";
    CHECK(tossed.cookie("session").empty());
    CHECK(tossed.cookie("lang") == "en");

    for (int round = 0; round < kStopRounds; ++round) {
        http::Server served(http::Server::Options{});
        served.get("/healthz", echo(captured));
        CHECK(served.start() > 0);
        std::thread other([&served]() { served.stop(); });
        served.stop();
        other.join();
        served.stop();
    }

    {
        http::Responder kept;
        std::atomic<bool> parked{false};
        boost::asio::io_context io;
        boost::asio::ip::tcp::socket asking(io);
        {
            http::Server served(http::Server::Options{});
            served.routeAsync("GET", "/later",
                [&kept, &parked](const http::Request&,
                    http::Responder respond) -> std::optional<http::Response> {
                    kept = std::move(respond);
                    parked.store(true);
                    return std::nullopt;
                });
            const int port = served.start();
            CHECK(port > 0);
            asking.connect(boost::asio::ip::tcp::endpoint(
                boost::asio::ip::make_address("127.0.0.1"), static_cast<unsigned short>(port)));
            const std::string held = "GET /later HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
            boost::asio::write(asking, boost::asio::buffer(held));
            const auto parkedBy = std::chrono::steady_clock::now() + kParkWithin;
            while (!parked.load() && std::chrono::steady_clock::now() < parkedBy) {
                std::this_thread::sleep_for(kParkPoll);
            }
            CHECK(parked.load());
        }
        kept(http::Response{});
    }
    return 0;
}
