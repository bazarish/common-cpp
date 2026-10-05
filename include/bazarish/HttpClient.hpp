// Bazarish project (c) 2026
#pragma once

#include <bazarish/HttpServer.hpp>

// Before Boost.Asio: awaitable.hpp (Boost 1.81, Debian 12) uses std::exchange
// without including <utility>, which libstdc++ 12 does not pull in on its own.
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

// The port a URL means when it names none.
inline constexpr int kDefaultHttpPort = 80;
inline constexpr int kDefaultHttpsPort = 443;

// Where a URL points, for a client that takes a host and a port rather than a
// URL. A URL that names no port means its scheme's; everything after the
// authority is the path a signature has to cover.
struct Url {
    std::string host;
    int port = kDefaultHttpPort;
    std::string path;
    bool tls = false;
};
Url parseUrl(const std::string& url);

// What to send upstream. The facade forwards verbatim, so the headers it was
// given (signatures included) travel unchanged.
struct ClientRequest {
    std::string method;
    std::string target;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string contentType;
};

// One HTTP exchange with a backend, asynchronously: the caller's coroutine is
// suspended, not its thread, which is what lets the facade forward a request
// the backend intends to hold open. A failure comes back as status 0.
boost::asio::awaitable<Response> fetch(boost::asio::any_io_executor executor,
    const std::string& host, int port, ClientRequest request, std::chrono::seconds timeout);

// How to reach the other end. The exchange itself is a coroutine either way;
// these are the parts a caller has to decide.
struct ClientOptions {
    bool tls = false;
    // Whether the peer's certificate is checked against the system trust store
    // and its host name. A caller whose security is anchored somewhere else (an
    // end-to-end signature, a pinned fingerprint) turns it off deliberately.
    bool verifyPeer = true;
    std::chrono::seconds connectTimeout{15};
    std::chrono::seconds readTimeout{60};
    std::chrono::seconds writeTimeout{60};
    // HTTP Digest credentials (RFC 7616), for a backend that asks for them -
    // monero-wallet-rpc does. Empty user: the exchange sends no credentials and
    // a 401 comes back to the caller as it stands.
    std::string digestUser;
    std::string digestPassword;
    // HTTP Basic credentials (RFC 7617), for a backend that takes only those -
    // bitcoind does, and its cookie file is a user and password like any other.
    // Sent with the first request rather than after a challenge, which is what
    // bitcoind expects and what saves a round trip on every call.
    std::string basicUser;
    std::string basicPassword;
};

struct ClientResponse {
    // 0 means the exchange never completed; `error` says why.
    int status = 0;
    std::map<std::string, std::string> headers;  // keys lowercased
    std::string body;
    std::string contentType;
    std::string error;
    // The request went out and the wait for an answer ran out. Not the same as
    // an unreachable host, and callers report the two differently.
    bool readTimedOut = false;
};

// One exchange for a caller that has no event loop of its own: it runs on a
// private one and returns when the answer is in. A transport failure is a
// status of 0, not an exception - the caller decides what an unreachable
// backend means.
ClientResponse request(
    const std::string& host, int port, const ClientRequest& request, const ClientOptions& options);

// Fills `chunk` with up to `capacity` bytes of the body and returns how many
// were written; 0 ends the body early.
using BodyProvider = std::function<std::size_t(char* chunk, std::size_t capacity)>;

// The same exchange with a body of known length streamed from somewhere else, so
// a multi-gigabyte upload is never held in memory. `request.body` is ignored.
ClientResponse upload(const std::string& host, int port, const ClientRequest& request,
    std::uint64_t length, const BodyProvider& provider, const ClientOptions& options);

}  // namespace bazarish::http
