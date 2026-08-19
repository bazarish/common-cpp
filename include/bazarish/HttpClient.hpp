// Bazarish project (c) 2026
#pragma once

#include <bazarish/HttpServer.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <map>
#include <string>

namespace bazarish::http {

// What to send upstream. The facade forwards verbatim, so the headers it was
// given (signatures included) travel unchanged.
struct ClientRequest {
    std::string method;
    std::string target;
    std::map<std::string, std::string> headers;
    std::string body;
};

// One HTTP exchange with a backend, asynchronously: the caller's coroutine is
// suspended, not its thread, which is what lets the facade forward a request
// the backend intends to hold open. A failure comes back as status 0.
boost::asio::awaitable<Response> fetch(boost::asio::any_io_executor executor,
    const std::string& host, int port, ClientRequest request, std::chrono::seconds timeout);

}  // namespace bazarish::http
