// Bazarish project (c) 2026
#pragma once

// Before Boost.Asio: awaitable.hpp (Boost 1.81, Debian 12) uses std::exchange
// without including <utility>, which libstdc++ 12 does not pull in on its own.
#include <utility>

#include <boost/asio/any_io_executor.hpp>

#include "bazarish/Auth.hpp"
#include "bazarish/Limits.hpp"

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::http {

// One HTTP engine for the whole fleet: Boost.Beast on an asio loop with C++20
// coroutines. It replaces the thread-per-request server, because a request that
// waits (the event face holds one open per client) must not hold a thread, and
// because two HTTP stacks in one binary means two parsers, two limits and two
// places for a bug like a head-size cap to hide.
struct Request {
    std::string method;
    std::string path;                             // without the query
    std::string target;                           // path + query, as signed
    std::map<std::string, std::string> headers;   // keys lowercased
    std::vector<std::string> captures;            // regex route captures, 1-based
    std::string body;

    std::string header(const std::string& name) const;
    // One cookie by name, empty when the request carries no such cookie. The
    // name is matched whole: a Cookie header holding "adminsession" does not
    // answer for "session", which is how one service's sign-in silently
    // answered for another's.
    std::string cookie(const std::string& name) const;
    // A value from the query string, percent-decoded.
    std::string query(const std::string& key) const;
    // The same, falling back to an urlencoded form body - what an HTML form
    // posts. A handler that serves both a link and a form reads one thing.
    std::string param(const std::string& key) const;
    bool hasHeader(const std::string& name) const;
};

struct Response {
    int status = 200;
    std::string contentType = "application/json";
    std::map<std::string, std::string> headers;
    std::string body;
};

// Most handlers answer on the spot.
using Handler = std::function<Response(const Request&)>;
// A handler that may answer later: it returns nullopt and calls `respond` when
// it has something. That is how a long poll is served without holding a thread.
using Responder = std::function<void(Response)>;
using AsyncHandler = std::function<std::optional<Response>(const Request&, Responder respond)>;

// Declared in WebSocket.hpp.
struct SocketRoutes;

// The authentication headers a request presents, under either scheme. Both sets
// are collected whatever the route accepts: a listener that gathered only the
// signature headers made every session-authenticated request look unsigned, and
// three copies of this in three components is how that happened in one of them.
auth::Headers collectAuthHeaders(const Request& request);

// Adapts a handler written as "fill in the response" to one that returns it.
// Several services are written that way; the engine hands a response back.
using Filler = std::function<void(const Request&, Response&)>;
Handler filled(Filler handler);

class Server {
public:
    struct Options {
        std::string host = "127.0.0.1";
        int port = 0;
        int threads = 4;
        // A signed request carries hybrid keys and a post-quantum signature:
        // ~8.3 KB of head before anything the caller sends.
        std::size_t maxHeadBytes = 64 * 1024;
        std::size_t maxBodyBytes = kMaxRequestBodyBytes;
        std::chrono::seconds readTimeout{120};
    };

    explicit Server(Options options);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Routes are matched in registration order; `pattern` is either a literal
    // path or an ECMAScript regex when it contains a capture group.
    void route(const std::string& method, const std::string& pattern, Handler handler);
    // Serves a WebSocket at this path, on this same listener. The routes are
    // declared in WebSocket.hpp, which a caller includes; taking them by value
    // here needs only the name.
    void upgrade(const std::string& pattern, SocketRoutes routes);
    void routeAsync(const std::string& method, const std::string& pattern, AsyncHandler handler);
    void get(const std::string& pattern, Handler handler);
    void getAsync(const std::string& pattern, AsyncHandler handler);
    void post(const std::string& pattern, Handler handler);
    void put(const std::string& pattern, Handler handler);
    void del(const std::string& pattern, Handler handler);

    // Runs a request through this server's own route table as if it had arrived
    // on a connection, answering through `respond`. It is what lets a transport
    // that carries requests inside something else - the client tunnel, where the
    // real method, path and headers are encrypted - reach the same handlers as a
    // plain request, rather than a second route table drifting beside this one.
    // An unmatched route answers 404 exactly as it would on the wire.
    void dispatch(const Request& request, Responder respond);

    // Binds and starts serving; returns the bound port (useful with port 0).
    int start();
    void stop();
    int port() const;
    // The loop handlers run on, for work that finishes a parked request.
    boost::asio::any_io_executor executor() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::http
