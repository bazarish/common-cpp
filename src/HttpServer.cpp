// Bazarish project (c) 2026
#include <bazarish/HttpServer.hpp>

#include <bazarish/Log.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <mutex>
#include <regex>
#include <thread>

namespace bazarish::http {

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;
using asio::ip::tcp;

std::string lowered(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

struct Route {
    std::string method;
    std::string pattern;
    std::regex matcher;
    bool isRegex = false;
    AsyncHandler handler;
};

}  // namespace

std::string Request::header(const std::string& name) const
{
    const auto found = headers.find(lowered(name));
    return found == headers.end() ? std::string() : found->second;
}

bool Request::hasHeader(const std::string& name) const
{
    return headers.find(lowered(name)) != headers.end();
}

std::string Request::query(const std::string& key) const
{
    const std::size_t mark = target.find('?');
    if (mark == std::string::npos) {
        return {};
    }
    std::string rest = target.substr(mark + 1);
    while (!rest.empty()) {
        const std::size_t amp = rest.find('&');
        const std::string pair = rest.substr(0, amp);
        const std::size_t eq = pair.find('=');
        if (eq != std::string::npos && pair.substr(0, eq) == key) {
            return pair.substr(eq + 1);
        }
        if (amp == std::string::npos) {
            break;
        }
        rest = rest.substr(amp + 1);
    }
    return {};
}

struct Server::Impl {
    Options options;
    asio::io_context io;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::vector<std::thread> workers;
    std::mutex routesMutex;
    std::vector<Route> routes;
    std::atomic<bool> stopping{false};

    explicit Impl(Options o)
        : options(std::move(o))
    {
    }

    const Route* match(const std::string& method, const std::string& path,
        std::vector<std::string>& captures) const;
    asio::awaitable<void> serve(tcp::socket socket);
    asio::awaitable<void> accept();
};

const Route* Server::Impl::match(const std::string& method, const std::string& path,
    std::vector<std::string>& captures) const
{
    for (const Route& route : routes) {
        if (route.method != method) {
            continue;
        }
        if (!route.isRegex) {
            if (route.pattern == path) {
                return &route;
            }
            continue;
        }
        std::smatch found;
        if (std::regex_match(path, found, route.matcher)) {
            captures.clear();
            for (std::size_t i = 1; i < found.size(); ++i) {
                captures.push_back(found[i].str());
            }
            return &route;
        }
    }
    return nullptr;
}

asio::awaitable<void> Server::Impl::serve(tcp::socket socket)
{
    beast::tcp_stream stream(std::move(socket));
    beast::flat_buffer buffer;
    try {
        for (;;) {
            stream.expires_after(options.readTimeout);
            http::request_parser<http::string_body> parser;
            parser.header_limit(static_cast<std::uint32_t>(options.maxHeadBytes));
            parser.body_limit(options.maxBodyBytes);
            boost::system::error_code readError;
            co_await http::async_read(
                stream, buffer, parser, asio::redirect_error(asio::use_awaitable, readError));
            if (readError) {
                break;  // peer closed, timed out, or sent something unparseable
            }
            const http::request<http::string_body> parsed = parser.release();

            Request request;
            request.method = std::string(parsed.method_string());
            request.target = std::string(parsed.target());
            const std::size_t mark = request.target.find('?');
            request.path
                = mark == std::string::npos ? request.target : request.target.substr(0, mark);
            for (const auto& field : parsed) {
                request.headers[lowered(std::string(field.name_string()))]
                    = std::string(field.value());
            }
            request.body = parsed.body();

            // The lock covers the lookup and nothing else. Holding it across the
            // await below would have parked the whole table for as long as one
            // client waited - which is what a long poll does by design.
            AsyncHandler handler;
            {
                const std::lock_guard<std::mutex> lock(routesMutex);
                if (const Route* const route
                    = match(request.method, request.path, request.captures);
                    route != nullptr) {
                    handler = route->handler;
                }
            }
            {
                if (handler) {
                    // A handler that answers later resumes this coroutine through
                    // the timer below, which is what makes a long poll free.
                    // Shared, not captured by reference: a responder may be called
                    // after this connection is gone (a gate that fires late), and a
                    // dangling timer would be a crash rather than a lost answer.
                    const auto executor = co_await asio::this_coro::executor;
                    const std::shared_ptr<asio::steady_timer> parked
                        = std::make_shared<asio::steady_timer>(executor);
                    parked->expires_at(std::chrono::steady_clock::time_point::max());
                    const std::shared_ptr<Response> answer = std::make_shared<Response>();
                    Responder respond = [parked, answer, executor](Response response) {
                        *answer = std::move(response);
                        asio::post(executor, [parked]() { parked->cancel(); });
                    };
                    std::optional<Response> immediate;
                    try {
                        immediate = handler(request, respond);
                    } catch (const std::exception& error) {
                        bazarish::log::warn("handler for {} threw: {}", request.path, error.what());
                        immediate = Response{500, "application/json",
                            {}, R"({"error":{"code":"DELIVERY_REJECTED","message":"internal error"}})"};
                    }
                    if (!immediate.has_value()) {
                        boost::system::error_code ignored;
                        co_await parked->async_wait(
                            asio::redirect_error(asio::use_awaitable, ignored));
                        immediate = *answer;
                    }
                    http::response<http::string_body> out{
                        static_cast<http::status>(immediate->status), parsed.version()};
                    if (!immediate->contentType.empty()) {
                        out.set(http::field::content_type, immediate->contentType);
                    }
                    for (const auto& header : immediate->headers) {
                        out.set(header.first, header.second);
                    }
                    out.body() = immediate->body;
                    out.keep_alive(parsed.keep_alive());
                    out.prepare_payload();
                    boost::system::error_code writeError;
                    stream.expires_after(options.readTimeout);
                    co_await http::async_write(
                        stream, out, asio::redirect_error(asio::use_awaitable, writeError));
                    if (writeError || !parsed.keep_alive()) {
                        break;
                    }
                    continue;
                }
            }
            http::response<http::string_body> out{http::status::not_found, parsed.version()};
            out.set(http::field::content_type, "application/json");
            out.body() = R"({"error":{"code":"DELIVERY_REJECTED","message":"unknown route"}})";
            out.keep_alive(parsed.keep_alive());
            out.prepare_payload();
            boost::system::error_code writeError;
            co_await http::async_write(
                stream, out, asio::redirect_error(asio::use_awaitable, writeError));
            if (writeError || !parsed.keep_alive()) {
                break;
            }
        }
    } catch (const std::exception& error) {
        bazarish::log::debug("connection ended: {}", error.what());
    }
    boost::system::error_code ignored;
    stream.socket().shutdown(tcp::socket::shutdown_both, ignored);
}

asio::awaitable<void> Server::Impl::accept()
{
    while (!stopping.load()) {
        boost::system::error_code acceptError;
        tcp::socket socket = co_await acceptor->async_accept(
            asio::redirect_error(asio::use_awaitable, acceptError));
        if (acceptError) {
            if (stopping.load()) {
                break;
            }
            bazarish::log::warn("accept failed: {}", acceptError.message());
            continue;
        }
        asio::co_spawn(io, serve(std::move(socket)), asio::detached);
    }
}

Server::Server(Options options)
    : impl_(std::make_unique<Impl>(std::move(options)))
{
}

Server::~Server()
{
    stop();
}

void Server::route(const std::string& method, const std::string& pattern, Handler handler)
{
    routeAsync(method, pattern,
        [handler = std::move(handler)](const Request& request, Responder) -> std::optional<Response> {
            return handler(request);
        });
}

void Server::routeAsync(const std::string& method, const std::string& pattern, AsyncHandler handler)
{
    Route entry;
    entry.method = method;
    entry.pattern = pattern;
    entry.isRegex = pattern.find('(') != std::string::npos;
    if (entry.isRegex) {
        entry.matcher = std::regex(pattern);
    }
    entry.handler = std::move(handler);
    const std::lock_guard<std::mutex> lock(impl_->routesMutex);
    impl_->routes.push_back(std::move(entry));
}

void Server::get(const std::string& pattern, Handler handler)
{
    route("GET", pattern, std::move(handler));
}

void Server::getAsync(const std::string& pattern, AsyncHandler handler)
{
    routeAsync("GET", pattern, std::move(handler));
}
void Server::post(const std::string& pattern, Handler handler)
{
    route("POST", pattern, std::move(handler));
}
void Server::put(const std::string& pattern, Handler handler)
{
    route("PUT", pattern, std::move(handler));
}
void Server::del(const std::string& pattern, Handler handler)
{
    route("DELETE", pattern, std::move(handler));
}

int Server::start()
{
    const tcp::endpoint endpoint(asio::ip::make_address(impl_->options.host),
        static_cast<unsigned short>(impl_->options.port));
    impl_->acceptor = std::make_unique<tcp::acceptor>(impl_->io);
    impl_->acceptor->open(endpoint.protocol());
    impl_->acceptor->set_option(asio::socket_base::reuse_address(true));
    impl_->acceptor->bind(endpoint);
    impl_->acceptor->listen(asio::socket_base::max_listen_connections);
    asio::co_spawn(impl_->io, impl_->accept(), asio::detached);
    for (int i = 0; i < std::max(1, impl_->options.threads); ++i) {
        impl_->workers.emplace_back([this]() { impl_->io.run(); });
    }
    return impl_->acceptor->local_endpoint().port();
}

void Server::stop()
{
    if (impl_->workers.empty()) {
        return;
    }
    impl_->stopping.store(true);
    boost::system::error_code ignored;
    impl_->acceptor->close(ignored);
    impl_->io.stop();
    for (std::thread& worker : impl_->workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    impl_->workers.clear();
}

asio::any_io_executor Server::executor() const
{
    return impl_->io.get_executor();
}

int Server::port() const
{
    return impl_->acceptor ? impl_->acceptor->local_endpoint().port() : 0;
}

}  // namespace bazarish::http
