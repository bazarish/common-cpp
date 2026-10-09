// Bazarish project (c) 2026
#pragma once

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

// One HTTP engine for the whole fleet: Boost.Beast on an asio loop with C++20 coroutines.
struct Request {
    std::string method;
    std::string path;
    std::string target;
    std::map<std::string, std::string> headers;
    std::vector<std::string> captures;
    std::string body;

    std::string header(const std::string& name) const;
    std::string cookie(const std::string& name) const;
    std::string query(const std::string& key) const;
    std::string param(const std::string& key) const;
    bool hasHeader(const std::string& name) const;
};

struct Response {
    int status = 200;
    std::string contentType = "application/json";
    std::map<std::string, std::string> headers;
    std::string body;
};

using Handler = std::function<Response(const Request&)>;
using Responder = std::function<void(Response)>;
using AsyncHandler = std::function<std::optional<Response>(const Request&, Responder respond)>;

struct SocketRoutes;

auth::Headers collectAuthHeaders(const Request& request);

std::optional<Response> operatorRefusal(const Request& request, std::int64_t now,
    const std::vector<std::string>& operators, auth::ReplayCache& replayCache);

using Filler = std::function<void(const Request&, Response&)>;
Handler filled(Filler handler);

class Server {
public:
    struct Options {
        std::string host = "127.0.0.1";
        int port = 0;
        int threads = 4;
        std::size_t maxHeadBytes = 64 * 1024;
        std::size_t maxBodyBytes = kMaxRequestBodyBytes;
        std::chrono::seconds readTimeout{120};
        std::string certificate;
        std::string key;
        std::vector<std::string> clientPins;
    };

    explicit Server(Options options);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    void route(const std::string& method, const std::string& pattern, Handler handler);
    void upgrade(const std::string& pattern, SocketRoutes routes);
    void routeAsync(const std::string& method, const std::string& pattern, AsyncHandler handler);
    void get(const std::string& pattern, Handler handler);
    void getAsync(const std::string& pattern, AsyncHandler handler);
    void post(const std::string& pattern, Handler handler);
    void put(const std::string& pattern, Handler handler);
    void del(const std::string& pattern, Handler handler);

    void dispatch(const Request& request, Responder respond);

    int start();
    void stop();
    int port() const;
    boost::asio::any_io_executor executor() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::http
