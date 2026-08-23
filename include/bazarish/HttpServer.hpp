// Bazarish project (c) 2026
#pragma once

#include <boost/asio/any_io_executor.hpp>

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

class Server {
public:
    struct Options {
        std::string host = "127.0.0.1";
        int port = 0;
        int threads = 4;
        // A signed request carries hybrid keys and a post-quantum signature:
        // ~8.3 KB of head before anything the caller sends.
        std::size_t maxHeadBytes = 64 * 1024;
        std::size_t maxBodyBytes = 64 * 1024 * 1024;
        std::chrono::seconds readTimeout{120};
    };

    explicit Server(Options options);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Routes are matched in registration order; `pattern` is either a literal
    // path or an ECMAScript regex when it contains a capture group.
    void route(const std::string& method, const std::string& pattern, Handler handler);
    void routeAsync(const std::string& method, const std::string& pattern, AsyncHandler handler);
    void get(const std::string& pattern, Handler handler);
    void getAsync(const std::string& pattern, AsyncHandler handler);
    void post(const std::string& pattern, Handler handler);
    void put(const std::string& pattern, Handler handler);
    void del(const std::string& pattern, Handler handler);

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
