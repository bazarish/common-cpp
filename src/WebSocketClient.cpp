// Bazarish project (c) 2026
#include "bazarish/WebSocketClient.hpp"

#include "bazarish/Log.hpp"

#include <utility>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>


#include <algorithm>
#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

namespace bazarish::http {

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace bhttp = boost::beast::http;
namespace ssl = boost::asio::ssl;
namespace websocket = boost::beast::websocket;
using asio::ip::tcp;

using TlsStream = beast::ssl_stream<beast::tcp_stream>;
using SteadyClock = std::chrono::steady_clock;

thread_local bool tOnSocketThread = false;

constexpr int kHttpVersion = 11;
constexpr std::size_t kKeptAnswerMaxBytes = 16 * 1024 * 1024;

bool isAddressLiteral(const std::string& host)
{
    boost::system::error_code error;
    (void)asio::ip::make_address(host, error);
    return !error;
}

// A literal IPv6 address names the host in brackets.
std::string hostHeader(const std::string& host)
{
    boost::system::error_code error;
    const asio::ip::address address = asio::ip::make_address(host, error);
    return !error && address.is_v6() ? "[" + host + "]" : host;
}

// One thread owns the stream: no concurrent callers, and Beast pings only for async operations.
template <class Stream>
class ClientSocket : public Socket, public std::enable_shared_from_this<ClientSocket<Stream>> {
public:
    ClientSocket(std::unique_ptr<asio::io_context> loop, std::unique_ptr<ssl::context> tls,
        std::unique_ptr<websocket::stream<Stream>> stream, const SocketDial& dial)
        : loop_(std::move(loop))
        , tls_(std::move(tls))
        , stream_(std::move(stream))
        , keepalive_(*loop_)
        , silence_(dial.pingAfterSilence)
        , pongWait_(dial.pongTimeout)
        , pingPayload_(dial.pingPayload)
    {
    }

    ~ClientSocket() override
    {
        open_.store(false);
        boost::system::error_code ignored;
        beast::get_lowest_layer(*stream_).socket().shutdown(tcp::socket::shutdown_both, ignored);
        if (!thread_.joinable()) {
            return;
        }
        if (thread_.get_id() == std::this_thread::get_id()) {
            // ownership: allowed - the socket's last owner was its own thread, which ends here.
            thread_.detach();
            return;
        }
        thread_.join();
    }

    void send(std::vector<unsigned char> message) override
    {
        bool start = false;
        {
            // Under the lock ended() takes: a write is never posted to a loop that has stopped.
            const std::lock_guard<std::mutex> lock(mutex_);
            if (!open_.load()) {
                return;
            }
            queued_ += message.size();
            queue_.push_back(std::move(message));
            start = !writing_;
            writing_ = true;
        }
        if (start) {
            asio::post(*loop_, [self = this->shared_from_this()]() { self->writeNext(); });
        }
    }

    std::size_t pending() const override
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return queued_;
    }

    void close() override
    {
        bool wasOpen = false;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            wasOpen = open_.exchange(false);
        }
        if (wasOpen) {
            asio::post(*loop_, [self = this->shared_from_this()]() {
                boost::system::error_code ignored;
                beast::get_lowest_layer(*self->stream_).socket().shutdown(
                    tcp::socket::shutdown_both, ignored);
            });
        }
        // A socket's own callbacks may close other sockets: waiting there could wait in a circle.
        if (tOnSocketThread) {
            return;
        }
        const std::lock_guard<std::mutex> lock(joinMutex_);
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    bool open() const override { return open_.load(); }

    void run(std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message,
        std::function<void(const SocketPtr&)> closed)
    {
        message_ = std::move(message);
        closed_ = std::move(closed);
        const std::shared_ptr<ClientSocket> self = this->shared_from_this();
        loop_->restart();
        if (silence_.count() > 0) {
            lastSent_ = SteadyClock::now();
            lastHeard_ = lastSent_;
            stream_->control_callback(
                [this](const websocket::frame_type, const beast::string_view) {
                    lastHeard_ = SteadyClock::now();
                });
            armKeepalive();
        }
        readNext();
        thread_ = std::thread([self]() {
            tOnSocketThread = true;
            self->loop_->run();
        });
    }

private:
    void readNext()
    {
        stream_->async_read(buffer_,
            [self = this->shared_from_this()](
                const boost::system::error_code& error, std::size_t) {
                self->delivered(error);
            });
    }

    void delivered(const boost::system::error_code& error)
    {
        if (error || !stream_->got_binary()) {
            if (error && open_.load()) {
                bazarish::log::info("websocket lost: {}", error.message());
            }
            ended();
            return;
        }
        lastHeard_ = SteadyClock::now();
        if (message_) {
            const unsigned char* const at = static_cast<const unsigned char*>(buffer_.data().data());
            message_(this->shared_from_this(), std::vector<unsigned char>(at, at + buffer_.size()));
        }
        buffer_.consume(buffer_.size());
        readNext();
    }

    void ended()
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            open_.store(false);
        }
        boost::system::error_code ignored;
        beast::get_lowest_layer(*stream_).socket().shutdown(tcp::socket::shutdown_both, ignored);
        websocket::stream_base::timeout off{};
        off.handshake_timeout = websocket::stream_base::none();
        off.idle_timeout = websocket::stream_base::none();
        off.keep_alive_pings = false;
        stream_->set_option(off);
        keepalive_.cancel();
        if (closed_) {
            closed_(this->shared_from_this());
        }
    }

    void writeNext()
    {
        // A deque keeps its front in place while others are pushed behind it.
        asio::const_buffer next;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty() || !open_.load()) {
                writing_ = false;
                return;
            }
            next = asio::buffer(queue_.front());
        }
        stream_->binary(true);
        stream_->async_write(next,
            [self = this->shared_from_this()](
                const boost::system::error_code& error, std::size_t) {
                {
                    const std::lock_guard<std::mutex> lock(self->mutex_);
                    self->queued_ -= self->queue_.front().size();
                    self->queue_.pop_front();
                }
                self->lastSent_ = SteadyClock::now();
                if (error) {
                    self->close();
                }
                self->writeNext();
            });
    }

    // A ping only after silence either way; one left unanswered past its wait ends the link.
    void armKeepalive()
    {
        const SteadyClock::time_point due = pingOut_
            ? pingSentAt_ + pongWait_
            : std::min(lastSent_, lastHeard_) + silence_;
        keepalive_.expires_at(due);
        keepalive_.async_wait(
            [self = this->shared_from_this()](const boost::system::error_code& error) {
                if (!error) {
                    self->keepaliveDue();
                }
            });
    }

    void keepaliveDue()
    {
        if (!open_.load()) {
            return;
        }
        const SteadyClock::time_point now = SteadyClock::now();
        if (pingOut_ && lastHeard_ >= pingSentAt_) {
            pingOut_ = false;
        }
        if (pingOut_ && now >= pingSentAt_ + pongWait_) {
            bazarish::log::info("websocket: a ping went unanswered for {} s; closed",
                pongWait_.count());
            close();
            return;
        }
        if (!pingOut_ && now - std::min(lastSent_, lastHeard_) >= silence_) {
            websocket::ping_data payload;
            if (pingPayload_) {
                const std::string carried = pingPayload_();
                payload.assign(carried.data(), std::min(carried.size(), payload.max_size()));
            }
            stream_->async_ping(payload,
                [self = this->shared_from_this()](const boost::system::error_code& error) {
                    if (error) {
                        self->close();
                    }
                });
            pingOut_ = true;
            pingSentAt_ = now;
            lastSent_ = now;
        }
        armKeepalive();
    }

    std::unique_ptr<asio::io_context> loop_;
    std::unique_ptr<ssl::context> tls_;
    std::unique_ptr<websocket::stream<Stream>> stream_;
    std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message_;
    std::function<void(const SocketPtr&)> closed_;
    beast::flat_buffer buffer_;
    std::thread thread_;
    std::mutex joinMutex_;
    mutable std::mutex mutex_;
    std::deque<std::vector<unsigned char>> queue_;
    std::size_t queued_ = 0;
    bool writing_ = false;
    std::atomic<bool> open_{true};
    asio::steady_timer keepalive_;
    const std::chrono::seconds silence_;
    const std::chrono::seconds pongWait_;
    const std::function<std::string()> pingPayload_;
    SteadyClock::time_point lastSent_{};
    SteadyClock::time_point lastHeard_{};
    SteadyClock::time_point pingSentAt_{};
    bool pingOut_ = false;
};

struct Connected {
    std::unique_ptr<asio::io_context> loop;
    std::unique_ptr<ssl::context> tls;
    std::unique_ptr<TlsStream> secure;
    std::unique_ptr<beast::tcp_stream> plain;
    std::string error;
};

// Beast's timeouts apply to asynchronous operations only.
template <class Start>
boost::system::error_code awaited(asio::io_context& loop, Start&& start)
{
    boost::system::error_code result;
    start([&result](const boost::system::error_code& error, auto&&...) { result = error; });
    loop.restart();
    loop.run();
    return result;
}

// Every connection to a host, a socket's or a plain request's, is made here.
Connected connect(const SocketDial& dial)
{
    Connected out;
    out.loop = std::make_unique<asio::io_context>();

    boost::system::error_code error;
    tcp::resolver resolver(*out.loop);
    const auto found = resolver.resolve(dial.host, std::to_string(dial.port), error);
    if (error) {
        out.error = "cannot find " + dial.host + ": " + error.message();
        return out;
    }

    if (!dial.tls) {
        out.plain = std::make_unique<beast::tcp_stream>(*out.loop);
        out.plain->expires_after(dial.connectTimeout);
        error = awaited(*out.loop, [&out, &found](auto&& handler) {
            out.plain->async_connect(found, std::move(handler));
        });
        if (error) {
            out.error = "cannot reach " + dial.host + ": " + error.message();
            return out;
        }
        out.plain->expires_never();
        boost::system::error_code ignoredOption;
        out.plain->socket().set_option(tcp::no_delay(true), ignoredOption);
        return out;
    }

    out.tls = std::make_unique<ssl::context>(ssl::context::tls_client);
    out.tls->set_verify_mode(ssl::verify_none);
    out.secure = std::make_unique<TlsStream>(*out.loop, *out.tls);

    if (!isAddressLiteral(dial.host)
        && SSL_set_tlsext_host_name(out.secure->native_handle(), dial.host.c_str()) != 1) {
        out.error = "the name would not go in the handshake";
        return out;
    }
    beast::get_lowest_layer(*out.secure).expires_after(dial.connectTimeout);
    error = awaited(*out.loop, [&out, &found](auto&& handler) {
        beast::get_lowest_layer(*out.secure).async_connect(found, std::move(handler));
    });
    if (error) {
        out.error = "cannot reach " + dial.host + ": " + error.message();
        return out;
    }
    beast::get_lowest_layer(*out.secure).expires_after(dial.connectTimeout);
    error = awaited(*out.loop, [&out](auto&& handler) {
        out.secure->async_handshake(ssl::stream_base::client, std::move(handler));
    });
    if (error) {
        out.error = "the handshake failed: " + error.message();
        return out;
    }

    beast::get_lowest_layer(*out.secure).expires_never();
    boost::system::error_code ignoredOption;
    beast::get_lowest_layer(*out.secure).socket().set_option(
        tcp::no_delay(true), ignoredOption);
    return out;
}

template <class Stream>
std::string upgrade(
    asio::io_context& loop, websocket::stream<Stream>& stream, const SocketDial& dial)
{
    websocket::stream_base::timeout timeouts{};
    timeouts.handshake_timeout = dial.connectTimeout;
    const bool ownKeepalive = dial.pingAfterSilence.count() > 0;
    timeouts.idle_timeout = ownKeepalive
        ? websocket::stream_base::none()
        : std::chrono::duration_cast<std::chrono::steady_clock::duration>(dial.idleTimeout);
    timeouts.keep_alive_pings = !ownKeepalive;
    stream.set_option(timeouts);
    stream.read_message_max(dial.maxMessageBytes);
    stream.set_option(
        websocket::stream_base::decorator([&dial](websocket::request_type& request) {
            for (const auto& [name, value] : dial.headers) {
                request.set(name, value);
            }
            if (!dial.subprotocol.empty()) {
                request.set(bhttp::field::sec_websocket_protocol, dial.subprotocol);
            }
        }));
    const boost::system::error_code error = awaited(loop, [&stream, &dial](auto&& handler) {
        stream.async_handshake(hostHeader(dial.host), dial.path, std::move(handler));
    });
    if (error) {
        return "the upgrade was refused: " + error.message();
    }
    stream.binary(true);
    return {};
}

}  // namespace

SocketDialResult openSocket(const SocketDial& dial,
    std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message,
    std::function<void(const SocketPtr&)> closed)
{
    SocketDialResult result;
    Connected connected = connect(dial);
    if (!connected.error.empty()) {
        result.error = connected.error;
        return result;
    }

    if (connected.plain) {
        auto stream
            = std::make_unique<websocket::stream<beast::tcp_stream>>(std::move(*connected.plain));
        result.error = upgrade(*connected.loop, *stream, dial);
        if (!result.error.empty()) {
            return result;
        }
        const auto socket = std::make_shared<ClientSocket<beast::tcp_stream>>(
            std::move(connected.loop), std::move(connected.tls), std::move(stream), dial);
        socket->run(std::move(message), std::move(closed));
        result.socket = socket;
        return result;
    }

    auto stream = std::make_unique<websocket::stream<TlsStream>>(std::move(*connected.secure));
    result.error = upgrade(*connected.loop, *stream, dial);
    if (!result.error.empty()) {
        return result;
    }
    const auto socket = std::make_shared<ClientSocket<TlsStream>>(
        std::move(connected.loop), std::move(connected.tls), std::move(stream), dial);
    socket->run(std::move(message), std::move(closed));
    result.socket = socket;
    return result;
}

namespace {

template <class Stream>
KeptAnswer exchange(asio::io_context& loop, Stream& stream, const SocketDial& dial,
    const std::string& target, const std::map<std::string, std::string>& headers)
{
    KeptAnswer answer;
    bhttp::request<bhttp::empty_body> out{bhttp::verb::get, target, kHttpVersion};
    out.set(bhttp::field::host, hostHeader(dial.host));
    for (const auto& [name, value] : headers) {
        out.set(name, value);
    }
    out.keep_alive(true);

    beast::get_lowest_layer(stream).expires_after(dial.connectTimeout);
    boost::system::error_code error = awaited(loop, [&stream, &out](auto&& handler) {
        bhttp::async_write(stream, out, std::move(handler));
    });
    if (error) {
        answer.error = "the request would not go: " + error.message();
        return answer;
    }
    beast::flat_buffer buffer;
    bhttp::response_parser<bhttp::string_body> in;
    in.body_limit(kKeptAnswerMaxBytes);
    beast::get_lowest_layer(stream).expires_after(dial.connectTimeout);
    error = awaited(loop, [&stream, &buffer, &in](auto&& handler) {
        bhttp::async_read(stream, buffer, in, std::move(handler));
    });
    beast::get_lowest_layer(stream).expires_never();
    if (error) {
        answer.error = "no answer came back: " + error.message();
        return answer;
    }
    answer.reached = true;
    answer.status = static_cast<int>(in.get().result_int());
    answer.bytes = in.get().body().size();
    return answer;
}

}  // namespace

struct KeptConnection::Impl {
    SocketDial dial;
    Connected connected;
    bool broken = false;
};

KeptConnection::KeptConnection(const SocketDial& dial)
    : impl_(std::make_unique<Impl>())
{
    impl_->dial = dial;
    impl_->connected = connect(dial);
}

KeptConnection::~KeptConnection()
{
    Connected& link = impl_->connected;
    if (!link.secure || !link.error.empty() || impl_->broken) {
        return;
    }
    beast::get_lowest_layer(*link.secure).expires_after(impl_->dial.connectTimeout);
    const boost::system::error_code error = awaited(*link.loop,
        [&link](auto&& handler) { link.secure->async_shutdown(std::move(handler)); });
    if (error) {
        bazarish::log::debug("a kept connection did not say goodbye: {}", error.message());
    }
}

bool KeptConnection::connected() const
{
    return impl_->connected.error.empty() && !impl_->broken;
}

const std::string& KeptConnection::error() const
{
    return impl_->connected.error;
}

KeptAnswer KeptConnection::get(
    const std::string& target, const std::map<std::string, std::string>& headers)
{
    if (!connected()) {
        KeptAnswer refused;
        refused.error = impl_->connected.error.empty() ? "the connection broke" : impl_->connected.error;
        return refused;
    }
    Connected& link = impl_->connected;
    const KeptAnswer answer = link.plain
        ? exchange(*link.loop, *link.plain, impl_->dial, target, headers)
        : exchange(*link.loop, *link.secure, impl_->dial, target, headers);
    impl_->broken = !answer.reached;
    return answer;
}

}  // namespace bazarish::http
