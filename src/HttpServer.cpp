// Bazarish project (c) 2026
#include <bazarish/HttpServer.hpp>

#include <bazarish/Errors.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/HttpResponses.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Percent.hpp>
#include <bazarish/PlainText.hpp>
#include <bazarish/Tls.hpp>
#include <bazarish/TlsContext.hpp>
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
#include <thread>

namespace bazarish::http {

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;
using asio::ip::tcp;

constexpr int kForbidden = 403;
constexpr int kMisdirected = 421;
// RFC 9110, 15.5.15.
constexpr int kUriTooLong = 414;

void denyFraming(const bool deny, Response& response)
{
    if (deny) {
        response.headers["X-Frame-Options"] = "DENY";
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'";
    }
}

std::string valueFrom(const std::string& encoded, const std::string& key)
{
    const std::optional<std::vector<QueryField>> fields = queryFields(encoded);
    if (!fields.has_value()) {
        return {};
    }
    for (const QueryField& field : *fields) {
        if (field.key == key) {
            return formDecode(field.value);
        }
    }
    return {};
}

enum class SegmentClass { eLiteral, eHex, eBase32, eLanguage, eOperation, eAssetName, eIdentifier,
    eAlias, eAnySegment };

struct RoutePart {
    SegmentClass kind = SegmentClass::eLiteral;
    std::string literal;
};

struct Route {
    std::string method;
    std::string pattern;
    bool everyPath = false;
    std::vector<RoutePart> parts;
    AsyncHandler handler;
};

struct Resolved {
    AsyncHandler handler;
    std::vector<std::string> captures;
};

constexpr char kEveryPath[] = "*";
constexpr std::string_view kNotInLiteral = "(){}[]*+?|\\^$";
constexpr char kPathSeparator = '/';

std::vector<std::string_view> pathSegments(const std::string_view path)
{
    std::vector<std::string_view> segments;
    std::size_t at = 0;
    while (at <= path.size()) {
        const std::size_t next = path.find(kPathSeparator, at);
        const std::size_t end = next == std::string_view::npos ? path.size() : next;
        segments.push_back(path.substr(at, end - at));
        if (next == std::string_view::npos) {
            break;
        }
        at = next + 1;
    }
    return segments;
}

SegmentClass segmentClassNamed(const std::string_view name)
{
    static const std::map<std::string_view, SegmentClass> kClasses = {
        {"hex", SegmentClass::eHex},
        {"b32", SegmentClass::eBase32},
        {"lang", SegmentClass::eLanguage},
        {"op", SegmentClass::eOperation},
        {"asset", SegmentClass::eAssetName},
        {"id", SegmentClass::eIdentifier},
        {"alias", SegmentClass::eAlias},
        {"segment", SegmentClass::eAnySegment},
    };
    const auto found = kClasses.find(name);
    if (found == kClasses.end()) {
        throw std::invalid_argument("unknown route segment class: " + std::string(name));
    }
    return found->second;
}

bool inClass(const SegmentClass kind, const char c)
{
    const bool lower = c >= 'a' && c <= 'z';
    const bool upper = c >= 'A' && c <= 'Z';
    const bool digit = c >= '0' && c <= '9';
    switch (kind) {
    case SegmentClass::eHex:
        return digit || (c >= 'a' && c <= 'f');
    case SegmentClass::eBase32:
        return lower || (c >= '2' && c <= '7');
    case SegmentClass::eLanguage:
        return lower || c == '-';
    case SegmentClass::eOperation:
        return lower || c == '.';
    case SegmentClass::eAssetName:
        return lower || upper || digit || c == '.' || c == '_' || c == '-';
    case SegmentClass::eIdentifier:
        return lower || digit || c == '_' || c == '-';
    case SegmentClass::eAlias:
        return lower || digit || c == '-';
    case SegmentClass::eAnySegment:
        return true;
    case SegmentClass::eLiteral:
        break;
    }
    return false;
}

Route routeFor(const std::string& method, const std::string& pattern, AsyncHandler handler)
{
    Route route;
    route.method = method;
    route.pattern = pattern;
    route.everyPath = pattern == kEveryPath;
    route.handler = std::move(handler);
    if (route.everyPath) {
        return route;
    }
    for (const std::string_view segment : pathSegments(pattern)) {
        RoutePart part;
        if (segment.size() > 2 && segment.front() == '{' && segment.back() == '}') {
            part.kind = segmentClassNamed(segment.substr(1, segment.size() - 2));
        } else if (segment.find_first_of(kNotInLiteral) != std::string_view::npos) {
            throw std::invalid_argument("a route segment is a literal or a {class}: " + pattern);
        } else {
            part.literal = std::string(segment);
        }
        route.parts.push_back(std::move(part));
    }
    return route;
}

std::optional<std::vector<std::string>> capturesOf(const Route& route, const std::string& path)
{
    if (route.everyPath) {
        return std::vector<std::string>{path};
    }
    const std::vector<std::string_view> segments = pathSegments(path);
    if (segments.size() != route.parts.size()) {
        return std::nullopt;
    }
    std::vector<std::string> captures;
    for (std::size_t i = 0; i < segments.size(); ++i) {
        const RoutePart& part = route.parts[i];
        if (part.kind == SegmentClass::eLiteral) {
            if (segments[i] != part.literal) {
                return std::nullopt;
            }
            continue;
        }
        if (segments[i].empty()
            || !std::all_of(segments[i].begin(), segments[i].end(),
                [&part](const char c) { return inClass(part.kind, c); })) {
            return std::nullopt;
        }
        captures.emplace_back(segments[i]);
    }
    return captures;
}

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
        , watchdog_(stream_.get_executor())
        , lastHeard_(std::chrono::steady_clock::now())
    {
    }

    void send(std::vector<unsigned char> message) override
    {
        if (!open_.load()) {
            return;
        }
        bool overflowing = false;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            overflowing = queued_ + message.size() > Server::kMaxSocketQueueBytes;
            if (!overflowing) {
                queued_ += message.size();
                queue_.push_back(std::move(message));
                if (writing_) {
                    return;
                }
                writing_ = true;
            }
        }
        if (overflowing) {
            log::warn("websocket: its reader is {} bytes behind; closed",
                Server::kMaxSocketQueueBytes);
            close();
            return;
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
    void markClosed()
    {
        open_.store(false);
        watchdog_.cancel();
    }

    // The read loop, the control callback and the watchdog all run on the stream's strand.
    void heard() { lastHeard_ = std::chrono::steady_clock::now(); }
    std::chrono::steady_clock::time_point lastHeard() const { return lastHeard_; }
    asio::steady_timer& watchdog() { return watchdog_; }

private:
    void write()
    {
        // A deque keeps its front in place while others are pushed behind it.
        asio::const_buffer front;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty()) {
                writing_ = false;
                return;
            }
            front = asio::buffer(queue_.front());
        }
        const std::shared_ptr<SocketImpl> self = shared_from_this();
        stream_.binary(true);
        stream_.async_write(front,
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
    asio::steady_timer watchdog_;
    std::chrono::steady_clock::time_point lastHeard_;
    mutable std::mutex mutex_;
    std::deque<std::vector<unsigned char>> queue_;
    std::size_t queued_ = 0;
    bool writing_ = false;
    std::atomic<bool> open_{true};
};

asio::awaitable<void> watchSilence(std::shared_ptr<SocketImpl> socket, std::chrono::seconds limit)
{
    while (socket->open()) {
        const std::chrono::steady_clock::time_point due = socket->lastHeard() + limit;
        if (std::chrono::steady_clock::now() >= due) {
            log::debug("websocket: nothing heard for {} s; closed", limit.count());
            socket->close();
            co_return;
        }
        socket->watchdog().expires_at(due);
        boost::system::error_code woken;
        co_await socket->watchdog().async_wait(asio::redirect_error(asio::use_awaitable, woken));
    }
}

asio::awaitable<void> runSocket(std::shared_ptr<SocketImpl> socket, Request request)
{
    websocket::stream<beast::tcp_stream>& stream = socket->stream();
    const SocketRoutes& routes = socket->routes();
    if (routes.silenceLimit.count() > 0) {
        const std::weak_ptr<SocketImpl> weak = socket;
        stream.control_callback(
            [weak](const websocket::frame_type kind, const beast::string_view payload) {
                const std::shared_ptr<SocketImpl> held = weak.lock();
                if (held == nullptr) {
                    return;
                }
                held->heard();
                if (kind == websocket::frame_type::ping && held->routes().pinged) {
                    held->routes().pinged(held, std::string(payload));
                }
            });
        asio::co_spawn(stream.get_executor(), watchSilence(socket, routes.silenceLimit),
            asio::detached);
    }
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
        socket->heard();
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

std::string hostName(const std::string& hostHeader)
{
    const std::string host = asciiLower(hostHeader);
    if (!host.empty() && host.front() == '[') {
        return host.substr(0, host.find(']') + 1);
    }
    const std::size_t colon = host.find(':');
    return colon != std::string::npos && host.find(':', colon + 1) == std::string::npos
        ? host.substr(0, colon)
        : host;
}

// Fetch Metadata: the browser names where a request came from, and no page can forge it.
bool crossSiteWrite(const Request& request)
{
    if (request.method == "GET" || request.method == "HEAD" || request.method == "OPTIONS") {
        return false;
    }
    const std::string site = request.header("Sec-Fetch-Site");
    return site == "cross-site" || site == "same-site";
}

}  // namespace

std::string Request::header(const std::string& name) const
{
    const auto found = headers.find(asciiLower(name));
    return found == headers.end() ? std::string() : found->second;
}

std::string Request::cookie(const std::string& name) const
{
    const std::string cookies = header("Cookie");
    std::optional<std::string> found;
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
            if (found.has_value()) {
                return {};
            }
            found = std::string(pair.substr(equals + 1));
        }
        at = end + 1;
    }
    return found.value_or(std::string());
}

bool Request::hasHeader(const std::string& name) const
{
    return headers.find(asciiLower(name)) != headers.end();
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
    if (!asciiLower(header("content-type")).starts_with("application/x-www-form-urlencoded")) {
        return {};
    }
    return valueFrom(body, key);
}

struct Server::Impl : std::enable_shared_from_this<Server::Impl> {
    Options options;
    asio::io_context io;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<boost::asio::ssl::context> tls;
    std::mutex lifecycleMutex;
    std::vector<std::thread> workers;
    mutable std::mutex routesMutex;
    std::vector<Route> routes;
    std::vector<SocketRoute> socketRoutes;
    std::atomic<bool> stopping{false};

    explicit Impl(Options o)
        : options(std::move(o))
    {
        for (std::string& host : options.hosts) {
            host = asciiLower(host);
        }
    }

    std::optional<Resolved> resolve(const Request& request) const;

    template <typename Stream>
    asio::awaitable<void> serveOn(Stream stream);
    asio::awaitable<void> serve(tcp::socket socket);
    asio::awaitable<void> serveTls(tcp::socket socket);
    asio::awaitable<void> accept();
};

std::optional<Resolved> Server::Impl::resolve(const Request& request) const
{
    const auto refusal = [](const int status, const std::string& why) {
        return Resolved{[status, why](const Request&, Responder) -> std::optional<Response> {
                            return errorResponse(status, ErrorCode::eRequestFailed, why);
                        },
            {}};
    };
    if (request.target.size() > options.maxTargetBytes) {
        return refusal(kUriTooLong, "the request target is too long");
    }
    if (!options.hosts.empty()
        && std::find(options.hosts.begin(), options.hosts.end(), hostName(request.header("Host")))
            == options.hosts.end()) {
        return refusal(kMisdirected, "this server does not answer for that host");
    }
    if (crossSiteWrite(request)) {
        return refusal(kForbidden, "a cross-site write is refused");
    }
    const std::lock_guard<std::mutex> lock(routesMutex);
    for (const Route& route : routes) {
        if (route.method != kAnyMethod && route.method != request.method) {
            continue;
        }
        if (std::optional<std::vector<std::string>> captures = capturesOf(route, request.path)) {
            return Resolved{route.handler, std::move(*captures)};
        }
    }
    return std::nullopt;
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
                request.headers[asciiLower(std::string(field.name_string()))]
                    = std::string(field.value());
            }
            request.body = parsed.body();

            if (websocket::is_upgrade(parsed)) {
                SocketRoutes chosen;
                bool matched = false;
                {
                    const std::lock_guard<std::mutex> lock(routesMutex);
                    for (const SocketRoute& route : socketRoutes) {
                        if (service::constantTimeEqual(route.pattern, request.path)) {
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
                            refusal = errorResponse(500, ErrorCode::eRequestFailed, "internal error");
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
                        out.keep_alive(parsed.keep_alive());
                        out.prepare_payload();
                        boost::system::error_code refusalError;
                        co_await http::async_write(stream, out,
                            asio::redirect_error(asio::use_awaitable, refusalError));
                        if (refusalError || !parsed.keep_alive()) {
                            break;
                        }
                        continue;
                    }
                    if constexpr (std::is_same_v<Stream, beast::tcp_stream>) {
                        // The request's read deadline would otherwise close the socket later.
                        beast::get_lowest_layer(stream).expires_never();
                        websocket::stream<beast::tcp_stream> upgraded(std::move(stream));
                        websocket::stream_base::timeout timeouts{};
                        timeouts.handshake_timeout = options.readTimeout;
                        const bool quiet = chosen.silenceLimit.count() > 0;
                        timeouts.idle_timeout = quiet
                            ? websocket::stream_base::none()
                            : std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                                chosen.idleTimeout);
                        timeouts.keep_alive_pings = !quiet;
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
            if (std::optional<Resolved> resolved = resolve(request)) {
                handler = std::move(resolved->handler);
                request.captures = std::move(resolved->captures);
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
                    const std::weak_ptr<Impl> alive = weak_from_this();
                    const std::weak_ptr<asio::steady_timer> waiting = parked;
                    // Weak: an answer that comes after the server is gone has nobody to go to.
                    // No executor kept: a strand outliving its io_context frees into a dead service.
                    Responder respond = [waiting, answer, answered, alive](Response response) {
                        *answer = std::move(response);
                        answered->store(true);
                        const std::shared_ptr<Impl> server = alive.lock();
                        const std::shared_ptr<asio::steady_timer> timer = waiting.lock();
                        if (server && timer) {
                            asio::post(timer->get_executor(),
                                [timer]() { timer->expires_at(std::chrono::steady_clock::now()); });
                        }
                    };
                    std::optional<Response> immediate;
                    try {
                        immediate = handler(request, respond);
                    } catch (const std::exception& error) {
                        bazarish::log::warn("handler for {} threw: {}", request.path, error.what());
                        immediate = errorResponse(500, ErrorCode::eRequestFailed, "internal error");
                    }
                    if (!immediate.has_value()) {
                        while (!answered->load()) {
                            boost::system::error_code ignored;
                            co_await parked->async_wait(
                                asio::redirect_error(asio::use_awaitable, ignored));
                        }
                        immediate = *answer;
                    }
                    denyFraming(options.denyFraming, *immediate);
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
    : impl_(std::make_shared<Impl>(std::move(options)))
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
    Route entry = routeFor(method, pattern, std::move(handler));
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

std::optional<Response> operatorRefusal(const Request& request, const std::int64_t now,
    const std::vector<std::string>& operators, auth::ReplayCache& replayCache)
{
    try {
        auth::authorizeRequest(collectAuthHeaders(request), now, request.method, request.target,
            Bytes(request.body.begin(), request.body.end()), operators, replayCache);
        return std::nullopt;
    } catch (const std::exception& error) {
        log::debug("an operator call was refused: {}", error.what());
        return errorResponse(403, ErrorCode::eRequestFailed, error.what());
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
    std::optional<Resolved> resolved = impl_->resolve(request);
    if (!resolved) {
        respond(errorResponse(404, ErrorCode::eRequestFailed, "no such route"));
        return;
    }
    Request routed = request;
    routed.captures = std::move(resolved->captures);
    const Responder framed = [deny = impl_->options.denyFraming, respond](Response response) {
        denyFraming(deny, response);
        respond(std::move(response));
    };
    std::optional<Response> answered;
    try {
        answered = resolved->handler(routed, framed);
    } catch (const std::exception& error) {
        log::warn("handler for {} threw: {}", request.path, error.what());
        answered = errorResponse(500, ErrorCode::eRequestFailed, "internal error");
    }
    if (answered.has_value()) {
        framed(std::move(*answered));
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
        impl_->tls = std::make_unique<ssl::context>(
            tls::serverContext(impl_->options.certificate, impl_->options.key));
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
    const int port = impl_->acceptor->local_endpoint().port();
    asio::co_spawn(impl_->io, impl_->accept(), asio::detached);
    {
        const std::lock_guard<std::mutex> lock(impl_->lifecycleMutex);
        for (int i = 0; i < std::max(1, impl_->options.threads); ++i) {
            impl_->workers.emplace_back([this]() { impl_->io.run(); });
        }
    }
    return port;
}

void Server::stop()
{
    const std::lock_guard<std::mutex> lock(impl_->lifecycleMutex);
    if (impl_->workers.empty()) {
        return;
    }
    impl_->stopping.store(true);
    impl_->io.stop();
    for (std::thread& worker : impl_->workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    impl_->workers.clear();
    // Only now: a worker may have been starting an accept on it.
    boost::system::error_code ignored;
    impl_->acceptor->close(ignored);
}

asio::any_io_executor Server::executor() const
{
    return impl_->io.get_executor();
}

int Server::port() const
{
    return impl_->acceptor ? impl_->acceptor->local_endpoint().port() : 0;
}

Response jsonResponse(const nlohmann::json& body, const int status)
{
    return Response{status, "application/json", {}, body.dump()};
}

Response errorResponse(const int status, const ErrorCode code, const std::string& message)
{
    return Response{status, "application/json", {}, makeErrorEnvelope(code, message).dump()};
}

}  // namespace bazarish::http
