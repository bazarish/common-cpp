// Bazarish project (c) 2026
#pragma once

#include <bazarish/HttpServer.hpp>

#include <utility>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>

namespace bazarish::http {

inline constexpr int kDefaultHttpPort = 80;
inline constexpr int kDefaultHttpsPort = 443;

struct Url {
    std::string host;
    int port = kDefaultHttpPort;
    std::string path;
    bool tls = false;
};
Url parseUrl(const std::string& url);

struct ClientRequest {
    std::string method;
    std::string target;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string contentType;
};

boost::asio::awaitable<Response> fetch(boost::asio::any_io_executor executor,
    const std::string& host, int port, ClientRequest request, std::chrono::seconds timeout);

struct ClientOptions {
    bool tls = false;
    bool verifyPeer = true;
    // A peer on a private socket is named by the hash of its key, not by a
    // chain and a hostname: with a pin set, that is the whole check.
    std::string pin;
    std::string certificate;
    std::string key;
    std::chrono::seconds connectTimeout{15};
    std::chrono::seconds readTimeout{60};
    std::chrono::seconds writeTimeout{60};
    std::string digestUser;
    std::string digestPassword;
    std::string basicUser;
    std::string basicPassword;
};

struct ClientResponse {
    int status = 0;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string contentType;
    std::string error;
    bool readTimedOut = false;
};

ClientResponse request(
    const std::string& host, int port, const ClientRequest& request, const ClientOptions& options);

using BodyProvider = std::function<std::size_t(char* chunk, std::size_t capacity)>;

ClientResponse upload(const std::string& host, int port, const ClientRequest& request,
    std::uint64_t length, const BodyProvider& provider, const ClientOptions& options);

}  // namespace bazarish::http
