// Bazarish project (c) 2026
#include <bazarish/HttpServer.hpp>

#include <bazarish/Errors.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Tls.hpp>
#include <bazarish/WebSocket.hpp>

#include <utility>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include <algorithm>
#include <string_view>
#include <atomic>
#include <cctype>
#include <deque>
#include <mutex>
#include <regex>
#include <thread>

namespace bazarish::http {

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;
using asio::ip::tcp;

constexpr std::size_t kEscapeDigits = 2;
constexpr int kHexBase = 16;

std::string lowered(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::string urlDecoded(const std::string& text)
{
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '+') {
            out.push_back(' ');
            continue;
        }
        if (text[i] == '%' && i + kEscapeDigits < text.size()
            && std::isxdigit(static_cast<unsigned char>(text[i + 1])) != 0
            && std::isxdigit(static_cast<unsigned char>(text[i + 2])) != 0) {
            out.push_back(static_cast<char>(
                std::stoi(text.substr(i + 1, kEscapeDigits), nullptr, kHexBase)));
            i += kEscapeDigits;
            continue;
        }
        out.push_back(text[i]);
    }
    return out;
}

std::string valueFrom(const std::string& encoded, const std::string& key)
{
    std::string rest = encoded;
    while (!rest.empty()) {
        const std::size_t amp = rest.find('&');
        const std::string pair = rest.substr(0, amp);
        const std::size_t eq = pair.find('=');
        if (eq != std::string::npos && pair.substr(0, eq) == key) {
            return urlDecoded(pair.substr(eq + 1));
        }
        if (amp == std::string::npos) {
            break;
        }
        rest = rest.substr(amp + 1);
    }
    return {};
}

struct Route {
    std::string method;
    std::string pattern;
    std::regex matcher;
    bool isRegex = false;
    AsyncHandler handler;
};

struct SocketRoute {
    std::string pattern;
    SocketRoutes routes;
};

namespace websocket = boost::beast::websocket;

class SocketImpl : public Socket, public std::enable_shared_from_this<SocketImpl> {
public:
    SocketImpl(websocket::stream<beast::tcp_stream> stream, SocketRoutes routes)
        : stream_(std::move(stream))
        , routes_(std::move(routes))
    {
    }

    void send(std::vector<unsigned char> message) override
    {
        if (!open_.load()) {
            return;
        }
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            queued_ += message.size();
            queue_.push_back(std::move(message));
            if (writing_) {
                return;
            }
            writing_ = true;
        }
        const std::shared_ptr<SocketImpl> self = shared_from_this();
        asio::post(stream_.get_executor(), [self]() { self->write(); });
    }

    std::size_t pending() const override
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return queued_;
    }

    void close() override
    {
        if (!open_.exchange(false)) {
            return;
        }
        const std::shared_ptr<SocketImpl> self = shared_from_this();
        asio::post(stream_.get_executor(), [self]() {
            boost::system::error_code ignored;
            self->stream_.next_layer().socket().shutdown(tcp::socket::shutdown_both, ignored);
        });
    }

    bool open() const override { return open_.load(); }

    websocket::stream<beast::tcp_stream>& stream() { return stream_; }
    const SocketRoutes& routes() const { return routes_; }
    void markClosed() { open_.store(false); }

private:
    void write()
    {
        std::vector<unsigned char>* front = nullptr;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty()) {
                writing_ = false;
                return;
            }
            front = &queue_.front();
        }
        const std::shared_ptr<SocketImpl> self = shared_from_this();
        stream_.binary(true);
        stream_.async_write(asio::buffer(*front),
            [self](const boost::system::error_code& error, const std::size_t) {
                {
                    const std::lock_guard<std::mutex> lock(self->mutex_);
                    self->queued_ -= self->queue_.front().size();
                    self->queue_.pop_front();
                    if (error) {
                        self->writing_ = false;
                    }
                }
                if (error) {
                    self->close();
                    return;
                }
                self->write();
            });
    }

    websocket::stream<beast::tcp_stream> stream_;
    SocketRoutes routes_;
    mutable std::mutex mutex_;
    std::deque<std::vector<unsigned char>> queue_;
    std::size_t queued_ = 0;
    bool writing_ = false;
    std::atomic<bool> open_{true};
};

asio::awaitable<void> runSocket(std::shared_ptr<SocketImpl> socket, Request request)
{
    websocket::stream<beast::tcp_stream>& stream = socket->stream();
    const SocketRoutes& routes = socket->routes();
    if (routes.opened) {
        routes.opened(socket, request);
    }
    beast::flat_buffer buffer;
    for (;;) {
        boost::system::error_code readError;
        co_await stream.async_read(
            buffer, asio::redirect_error(asio::use_awaitable, readError));
        if (readError) {
            break;
        }
        if (!stream.got_binary()) {
            break;
        }
        if (routes.message) {
            const unsigned char* const at
                = static_cast<const unsigned char*>(buffer.data().data());
            routes.message(socket, std::vector<unsigned char>(at, at + buffer.size()));
        }
        buffer.consume(buffer.size());
    }
    socket->markClosed();
    if (routes.closed) {
        routes.closed(socket);
    }
}

}  // namespace

std::string Request::header(const std::string& name) const
{
    const auto found = headers.find(lowered(name));
    return found == headers.end() ? std::string() : found->second;
}

std::string Request::cookie(const std::string& name) const
{
    const std::string cookies = header("Cookie");
    std::size_t at = 0;
    while (at < cookies.size()) {
        std::size_t end = cookies.find(';', at);
        if (end == std::string::npos) {
            end = cookies.size();
        }
        std::string_view pair(cookies.data() + at, end - at);
        while (!pair.empty() && (pair.front() == ' ' || pair.front() == '\t')) {
            pair.remove_prefix(1);
        }
        const std::size_t equals = pair.find('=');
        if (equals != std::string_view::npos && pair.substr(0, equals) == name) {
            return std::string(pair.substr(equals + 1));
        }
        at = end + 1;
    }
    return {};
}

bool Request::hasHeader(const std::string& name) const
{
    return headers.find(lowered(name)) != headers.end();
}

std::string Request::query(const std::string& key) const
{
    const std::size_t mark = target.find('?');
    return mark == std::string::npos ? std::string() : valueFrom(target.substr(mark + 1), key);
}

std::string Request::param(const std::string& key) const
{
    const std::string fromQuery = query(key);
    if (!fromQuery.empty()) {
        return fromQuery;
    }
    if (lowered(header("content-type")).rfind("application/x-www-form-urlencoded", 0) != 0) {
        return {};
    }
    return valueFrom(body, key);
}

struct Server::Impl {
    Options options;
    asio::io_context io;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<boost::asio::ssl::context> tls;
    std::vector<std::thread> workers;
    std::mutex routesMutex;
    std::vector<Route> routes;
    std::vector<SocketRoute> socketRoutes;
    std::atomic<bool> stopping{false};

    explicit Impl(Options o)
        : options(std::move(o))
    {
    }

    const Route* match(const std::string& method, const std::string& path,
        std::vector<std::string>& captures) const;
    template <typename Stream>
    asio::awaitable<void> serveOn(Stream stream);
    asio::awaitable<void> serve(tcp::socket socket);
    asio::awaitable<void> serveTls(tcp::socket socket);
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

template <typename Stream>
asio::awaitable<void> Server::Impl::serveOn(Stream stream)
{
    beast::flat_buffer buffer;
    try {
        for (;;) {
            beast::get_lowest_layer(stream).expires_after(options.readTimeout);
            http::request_parser<http::string_body> parser;
            parser.header_limit(static_cast<std::uint32_t>(options.maxHeadBytes));
            parser.body_limit(options.maxBodyBytes);
            boost::system::error_code readError;
            co_await http::async_read(
                stream, buffer, parser, asio::redirect_error(asio::use_awaitable, readError));
            if (readError) {
                break;
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

            if (websocket::is_upgrade(parsed)) {
                SocketRoutes chosen;
                bool matched = false;
                {
                    const std::lock_guard<std::mutex> lock(routesMutex);
                    for (const SocketRoute& route : socketRoutes) {
                        if (route.pattern == request.path) {
                            chosen = route.routes;
                            matched = true;
                            break;
                        }
                    }
                }
                if (matched) {
                    std::optional<Response> refusal;
                    if (chosen.admit) {
                        try {
                            refusal = chosen.admit(request);
                        } catch (const std::exception& error) {
                            bazarish::log::warn(
                                "upgrade check for {} threw: {}", request.path, error.what());
                            refusal = Response{500, "application/json", {},
                                R"({"error":{"code":"DELIVERY_REJECTED","message":"internal error"}})"};
                        }
                    }
                    if (refusal.has_value()) {
                        http::response<http::string_body> out{
                            static_cast<http::status>(refusal->status), parsed.version()};
                        if (!refusal->contentType.empty()) {
                            out.set(http::field::content_type, refusal->contentType);
                        }
                        for (const auto& header : refusal->headers) {
                            out.set(header.first, header.second);
                        }
                        out.body() = refusal->body;
                        out.keep_alive(false);
                        out.prepare_payload();
                        boost::system::error_code refusalError;
                        co_await http::async_write(stream, out,
                            asio::redirect_error(asio::use_awaitable, refusalError));
                        break;
                    }
                    if constexpr (std::is_same_v<Stream, beast::tcp_stream>) {
                        websocket::stream<beast::tcp_stream> upgraded(std::move(stream));
                        websocket::stream_base::timeout timeouts{};
                        timeouts.handshake_timeout = options.readTimeout;
                        timeouts.idle_timeout = chosen.idleTimeout;
                        timeouts.keep_alive_pings = true;
                        upgraded.set_option(timeouts);
                        upgraded.set_option(websocket::stream_base::decorator(
                            [protocol = chosen.subprotocol](websocket::response_type& response) {
                                if (!protocol.empty()) {
                                    response.set(http::field::sec_websocket_protocol, protocol);
                                }
                            }));
                        upgraded.read_message_max(chosen.maxMessageBytes);
                        boost::system::error_code upgradeError;
                        co_await upgraded.async_accept(
                            parsed, asio::redirect_error(asio::use_awaitable, upgradeError));
                        if (upgradeError) {
                            co_return;
                        }
                        co_await runSocket(
                            std::make_shared<SocketImpl>(std::move(upgraded), std::move(chosen)),
                            request);
                        co_return;
                    }
                }
            }

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
                    const auto executor = co_await asio::this_coro::executor;
                    const std::shared_ptr<asio::steady_timer> parked
                        = std::make_shared<asio::steady_timer>(executor);
                    parked->expires_at(std::chrono::steady_clock::time_point::max());
                    const std::shared_ptr<Response> answer = std::make_shared<Response>();
                    const std::shared_ptr<std::atomic<bool>> answered
                        = std::make_shared<std::atomic<bool>>(false);
                    Responder respond = [parked, answer, executor, answered](Response response) {
                        *answer = std::move(response);
                        answered->store(true);
                        asio::post(executor,
                            [parked]() { parked->expires_at(std::chrono::steady_clock::now()); });
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
                        while (!answered->load()) {
                            boost::system::error_code ignored;
                            co_await parked->async_wait(
                                asio::redirect_error(asio::use_awaitable, ignored));
                        }
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
                    beast::get_lowest_layer(stream).expires_after(options.readTimeout);
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
    beast::get_lowest_layer(stream).socket().shutdown(tcp::socket::shutdown_both, ignored);
}

asio::awaitable<void> Server::Impl::serve(tcp::socket socket)
{
    co_await serveOn(beast::tcp_stream(std::move(socket)));
}

asio::awaitable<void> Server::Impl::serveTls(tcp::socket socket)
{
    namespace ssl = boost::asio::ssl;
    beast::ssl_stream<beast::tcp_stream> stream(std::move(socket), *tls);
    beast::get_lowest_layer(stream).expires_after(options.readTimeout);
    boost::system::error_code handshakeError;
    co_await stream.async_handshake(
        ssl::stream_base::server, asio::redirect_error(asio::use_awaitable, handshakeError));
    if (handshakeError) {
        bazarish::log::debug("a handshake did not finish: {}", handshakeError.message());
        co_return;
    }
    if (!options.clientPins.empty()) {
        const std::string pin = bazarish::tls::pinOf(stream.native_handle());
        if (std::find(options.clientPins.begin(), options.clientPins.end(), pin)
            == options.clientPins.end()) {
            bazarish::log::warn("a caller with an unlisted key was refused");
            co_return;
        }
    }
    co_await serveOn(std::move(stream));
}

asio::awaitable<void> Server::Impl::accept()
{
    while (!stopping.load()) {
        boost::system::error_code acceptError;
        tcp::socket socket(asio::make_strand(io));
        co_await acceptor->async_accept(
            socket, asio::redirect_error(asio::use_awaitable, acceptError));
        if (!acceptError) {
            boost::system::error_code ignored;
            socket.set_option(tcp::no_delay(true), ignored);
        }
        if (acceptError) {
            if (stopping.load()) {
                break;
            }
            bazarish::log::warn("accept failed: {}", acceptError.message());
            continue;
        }
        const asio::any_io_executor executor = socket.get_executor();
        if (tls) {
            asio::co_spawn(executor, serveTls(std::move(socket)), asio::detached);
        } else {
            asio::co_spawn(executor, serve(std::move(socket)), asio::detached);
        }
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

void Server::upgrade(const std::string& pattern, SocketRoutes routes)
{
    const std::lock_guard<std::mutex> lock(impl_->routesMutex);
    impl_->socketRoutes.push_back(SocketRoute{pattern, std::move(routes)});
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

auth::Headers collectAuthHeaders(const Request& request)
{
    auth::Headers headers;
    for (const char* const name : {auth::kHeaderKeys, auth::kHeaderTimestamp,
             auth::kHeaderNonce, auth::kHeaderSignatureClassical, auth::kHeaderSignaturePq,
             auth::kHeaderSession, auth::kHeaderSeq, auth::kHeaderMac}) {
        if (request.hasHeader(name)) {
            headers[name] = request.header(name);
        }
    }
    return headers;
}

std::optional<Response> operatorRefusal(
    const Request& request, const std::int64_t now, const std::vector<std::string>& operators)
{
    try {
        auth::authorizeRequest(collectAuthHeaders(request), now, request.method, request.path,
            Bytes(request.body.begin(), request.body.end()), operators);
        return std::nullopt;
    } catch (const std::exception& error) {
        log::debug("an operator call was refused: {}", error.what());
        return Response{403, "application/json", {},
            makeErrorEnvelope(ErrorCode::eDeliveryRejected, error.what()).dump()};
    }
}

Handler filled(Filler handler)
{
    return [handler = std::move(handler)](const Request& request) {
        Response response;
        handler(request, response);
        return response;
    };
}

void Server::dispatch(const Request& request, Responder respond)
{
    const Route* route = nullptr;
    std::vector<std::string> captures;
    {
        const std::lock_guard<std::mutex> lock(impl_->routesMutex);
        route = impl_->match(request.method, request.path, captures);
    }
    if (route == nullptr) {
        Response missing;
        missing.status = 404;
        missing.body = R"({"error":{"message":"no such route"}})";
        respond(std::move(missing));
        return;
    }
    Request routed = request;
    routed.captures = captures;
    std::optional<Response> answered;
    try {
        answered = route->handler(routed, respond);
    } catch (const std::exception& error) {
        log::warn("handler for {} threw: {}", request.path, error.what());
        answered = Response{500, "application/json", {},
            R"({"error":{"code":"DELIVERY_REJECTED","message":"internal error"}})"};
    }
    if (answered.has_value()) {
        respond(std::move(*answered));
    }
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
    if (!impl_->options.certificate.empty()) {
        namespace ssl = boost::asio::ssl;
        impl_->tls = std::make_unique<ssl::context>(ssl::context::tls_server);
        impl_->tls->set_options(ssl::context::default_workarounds | ssl::context::no_sslv2
            | ssl::context::no_sslv3);
        impl_->tls->use_certificate_chain_file(impl_->options.certificate);
        impl_->tls->use_private_key_file(impl_->options.key, ssl::context::pem);
        if (!impl_->options.clientPins.empty()) {
            impl_->tls->set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
            impl_->tls->set_verify_callback([](bool, ssl::verify_context&) { return true; });
        }
    }
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
