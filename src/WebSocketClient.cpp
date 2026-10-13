// Bazarish project (c) 2026
#include "bazarish/WebSocketClient.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/Log.hpp"

#include <utility>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <openssl/x509.h>

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

std::string spkiFingerprint(SSL* const connection)
{
    X509* const certificate = SSL_get1_peer_certificate(connection);
    if (certificate == nullptr) {
        return {};
    }
    unsigned char* der = nullptr;
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &der);
    std::string fingerprint;
    if (length > 0 && der != nullptr) {
        fingerprint = toHex(sha256(Bytes(der, der + length)));
    }
    OPENSSL_free(der);
    X509_free(certificate);
    return fingerprint;
}

// One thread owns the stream: Beast's and OpenSSL's streams take no concurrent callers, and
// Beast keeps its idle timeout and pings only for asynchronous operations.
template <class Stream>
class ClientSocket : public Socket, public std::enable_shared_from_this<ClientSocket<Stream>> {
public:
    ClientSocket(std::unique_ptr<asio::io_context> loop, std::unique_ptr<ssl::context> tls,
        std::unique_ptr<websocket::stream<Stream>> stream)
        : loop_(std::move(loop))
        , tls_(std::move(tls))
        , stream_(std::move(stream))
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
            thread_.detach();
            return;
        }
        thread_.join();
    }

    void send(std::vector<unsigned char> message) override
    {
        if (!open_.load()) {
            return;
        }
        bool start = false;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
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
        if (!open_.exchange(false)) {
            return;
        }
        asio::post(*loop_, [self = this->shared_from_this()]() {
            boost::system::error_code ignored;
            beast::get_lowest_layer(*self->stream_).socket().shutdown(
                tcp::socket::shutdown_both, ignored);
        });
    }

    bool open() const override { return open_.load(); }

    void run(std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message,
        std::function<void(const SocketPtr&)> closed)
    {
        message_ = std::move(message);
        closed_ = std::move(closed);
        const std::shared_ptr<ClientSocket> self = this->shared_from_this();
        loop_->restart();
        readNext();
        thread_ = std::thread([self]() { self->loop_->run(); });
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
        if (message_) {
            const unsigned char* const at = static_cast<const unsigned char*>(buffer_.data().data());
            message_(this->shared_from_this(), std::vector<unsigned char>(at, at + buffer_.size()));
        }
        buffer_.consume(buffer_.size());
        readNext();
    }

    void ended()
    {
        open_.store(false);
        boost::system::error_code ignored;
        beast::get_lowest_layer(*stream_).socket().shutdown(tcp::socket::shutdown_both, ignored);
        if (closed_) {
            closed_(this->shared_from_this());
        }
    }

    void writeNext()
    {
        const std::vector<unsigned char>* next = nullptr;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty() || !open_.load()) {
                writing_ = false;
                return;
            }
            next = &queue_.front();
        }
        stream_->binary(true);
        stream_->async_write(asio::buffer(*next),
            [self = this->shared_from_this()](
                const boost::system::error_code& error, std::size_t) {
                {
                    const std::lock_guard<std::mutex> lock(self->mutex_);
                    self->queued_ -= self->queue_.front().size();
                    self->queue_.pop_front();
                }
                if (error) {
                    self->close();
                }
                self->writeNext();
            });
    }

    std::unique_ptr<asio::io_context> loop_;
    std::unique_ptr<ssl::context> tls_;
    std::unique_ptr<websocket::stream<Stream>> stream_;
    std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message_;
    std::function<void(const SocketPtr&)> closed_;
    beast::flat_buffer buffer_;
    std::thread thread_;
    mutable std::mutex mutex_;
    std::deque<std::vector<unsigned char>> queue_;
    std::size_t queued_ = 0;
    bool writing_ = false;
    std::atomic<bool> open_{true};
};

struct Connected {
    std::unique_ptr<asio::io_context> loop;
    std::unique_ptr<ssl::context> tls;
    std::unique_ptr<TlsStream> secure;
    std::unique_ptr<beast::tcp_stream> plain;
    std::string pin;
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

    out.tls = std::make_unique<ssl::context>(ssl::context::tlsv12_client);
    out.tls->set_verify_mode(ssl::verify_none);
    out.secure = std::make_unique<TlsStream>(*out.loop, *out.tls);

    const std::string sni = dial.sni.empty() ? dial.host : dial.sni;
    if (SSL_set_tlsext_host_name(out.secure->native_handle(), sni.c_str()) != 1) {
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

    out.pin = spkiFingerprint(out.secure->native_handle());
    if (out.pin.empty()) {
        out.error = "the peer presented no key";
        return out;
    }
    if (!dial.pin.empty() && dial.pin != out.pin) {
        out.error = "the peer's key is not the pinned one";
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
    timeouts.idle_timeout = dial.idleTimeout;
    timeouts.keep_alive_pings = true;
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
    const std::string host = dial.sni.empty() ? dial.host : dial.sni;
    const boost::system::error_code error = awaited(loop, [&stream, &host, &dial](auto&& handler) {
        stream.async_handshake(host, dial.path, std::move(handler));
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
    result.pin = connected.pin;
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
            std::move(connected.loop), std::move(connected.tls), std::move(stream));
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
        std::move(connected.loop), std::move(connected.tls), std::move(stream));
    socket->run(std::move(message), std::move(closed));
    result.socket = socket;
    return result;
}

namespace {

template <class Stream>
void exchange(asio::io_context& loop, Stream& stream, const SocketDial& dial,
    const std::string& body, Probe& probe)
{
    bhttp::request<bhttp::string_body> out{
        body.empty() ? bhttp::verb::get : bhttp::verb::post, dial.path, 11};
    out.set(bhttp::field::host, dial.sni.empty() ? dial.host : dial.sni);
    for (const auto& [name, value] : dial.headers) {
        out.set(name, value);
    }
    out.body() = body;
    out.prepare_payload();

    beast::get_lowest_layer(stream).expires_after(dial.connectTimeout);
    boost::system::error_code error = awaited(loop, [&stream, &out](auto&& handler) {
        bhttp::async_write(stream, out, std::move(handler));
    });
    if (error) {
        probe.error = "the request would not go: " + error.message();
        return;
    }
    beast::flat_buffer buffer;
    bhttp::response<bhttp::string_body> in;
    beast::get_lowest_layer(stream).expires_after(dial.connectTimeout);
    error = awaited(loop, [&stream, &buffer, &in](auto&& handler) {
        bhttp::async_read(stream, buffer, in, std::move(handler));
    });
    if (error) {
        probe.error = "no answer came back: " + error.message();
        return;
    }
    probe.reached = true;
    probe.status = static_cast<int>(in.result_int());
}

}  // namespace

Probe probeHost(const SocketDial& dial, const std::string& body)
{
    Probe probe;
    Connected connected = connect(dial);
    probe.pin = connected.pin;
    if (!connected.error.empty()) {
        probe.error = connected.error;
        return probe;
    }
    if (connected.plain) {
        exchange(*connected.loop, *connected.plain, dial, body, probe);
        return probe;
    }
    exchange(*connected.loop, *connected.secure, dial, body, probe);
    boost::system::error_code ignored;
    connected.secure->shutdown(ignored);
    return probe;
}

}  // namespace bazarish::http
