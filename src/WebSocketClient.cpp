// Bazarish project (c) 2026
#include "bazarish/WebSocketClient.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/Log.hpp"

// Before any Boost.Asio header: awaitable.hpp (Boost 1.81, Debian 12) uses
// std::exchange without including <utility>, which libstdc++ 12 does not pull in
// on its own.
#include <utility>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
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

// The key a certificate carries, which is what a pin names. The certificate
// around it may be reissued, renamed or self-signed without the pin caring:
// what must not change is the key.
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

// One socket the client owns, and the loop it runs on. The stream is either
// plain or wrapped in TLS; nothing else about the socket differs.
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
        close();
        if (worker_.joinable()) {
            worker_.join();
        }
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
        const std::shared_ptr<ClientSocket> self = this->shared_from_this();
        asio::post(loop_->get_executor(), [self]() { self->write(); });
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
        const std::shared_ptr<ClientSocket> self = this->shared_from_this();
        asio::post(loop_->get_executor(), [self]() {
            boost::system::error_code ignored;
            beast::get_lowest_layer(*self->stream_).socket().shutdown(
                tcp::socket::shutdown_both, ignored);
        });
    }

    bool open() const override { return open_.load(); }

    void run(std::function<void(const SocketPtr&, const std::vector<unsigned char>&)> message,
        std::function<void(const SocketPtr&)> closed)
    {
        const std::shared_ptr<ClientSocket> self = this->shared_from_this();
        worker_ = std::thread([self, message = std::move(message), closed = std::move(closed)]() {
            self->read(message, closed);
            self->loop_->run();
        });
    }

private:
    void read(const std::function<void(const SocketPtr&, const std::vector<unsigned char>&)>&
                  message,
        const std::function<void(const SocketPtr&)>& closed)
    {
        const std::shared_ptr<ClientSocket> self = this->shared_from_this();
        std::thread([self, message, closed]() {
            beast::flat_buffer buffer;
            for (;;) {
                boost::system::error_code error;
                self->stream_->read(buffer, error);
                if (error) {
                    break;
                }
                if (!self->stream_->got_binary()) {
                    break;
                }
                if (message) {
                    const unsigned char* const at
                        = static_cast<const unsigned char*>(buffer.data().data());
                    message(self, std::vector<unsigned char>(at, at + buffer.size()));
                }
                buffer.consume(buffer.size());
            }
            self->open_.store(false);
            if (closed) {
                closed(self);
            }
            self->loop_->stop();
        }).detach();
    }

    void write()
    {
        std::vector<unsigned char> message;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty()) {
                writing_ = false;
                return;
            }
            message = queue_.front();
        }
        boost::system::error_code error;
        stream_->binary(true);
        stream_->write(asio::buffer(message), error);
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            queued_ -= queue_.front().size();
            queue_.pop_front();
            if (error) {
                writing_ = false;
            }
        }
        if (error) {
            close();
            return;
        }
        const std::shared_ptr<ClientSocket> self = this->shared_from_this();
        asio::post(loop_->get_executor(), [self]() { self->write(); });
    }

    std::unique_ptr<asio::io_context> loop_;
    std::unique_ptr<ssl::context> tls_;
    std::unique_ptr<websocket::stream<Stream>> stream_;
    std::thread worker_;
    mutable std::mutex mutex_;
    std::deque<std::vector<unsigned char>> queue_;
    std::size_t queued_ = 0;
    bool writing_ = false;
    std::atomic<bool> open_{true};
};

// Connects and shakes hands. Over TLS the pin is what decides whether the peer
// is the right one; nothing else does.
struct Connected {
    std::unique_ptr<asio::io_context> loop;
    std::unique_ptr<ssl::context> tls;
    std::unique_ptr<TlsStream> secure;
    std::unique_ptr<beast::tcp_stream> plain;
    std::string pin;
    std::string error;
};

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
        out.plain->connect(found, error);
        if (error) {
            out.error = "cannot reach " + dial.host + ": " + error.message();
            return out;
        }
        out.plain->expires_never();
        return out;
    }

    out.tls = std::make_unique<ssl::context>(ssl::context::tlsv12_client);
    // The pin is the whole of the check, so the chain is not one: a gateway
    // needs no CA-issued certificate and no real host name.
    out.tls->set_verify_mode(ssl::verify_none);
    out.secure = std::make_unique<TlsStream>(*out.loop, *out.tls);

    const std::string sni = dial.sni.empty() ? dial.host : dial.sni;
    if (SSL_set_tlsext_host_name(out.secure->native_handle(), sni.c_str()) != 1) {
        out.error = "the name would not go in the handshake";
        return out;
    }
    beast::get_lowest_layer(*out.secure).expires_after(dial.connectTimeout);
    beast::get_lowest_layer(*out.secure).connect(found, error);
    if (error) {
        out.error = "cannot reach " + dial.host + ": " + error.message();
        return out;
    }
    out.secure->handshake(ssl::stream_base::client, error);
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
        // Not a warning and not a question: this is a different peer.
        out.error = "the peer's key is not the pinned one";
        return out;
    }
    beast::get_lowest_layer(*out.secure).expires_never();
    return out;
}

// The upgrade, once a stream of either kind is standing.
template <class Stream>
std::string upgrade(websocket::stream<Stream>& stream, const SocketDial& dial)
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
    boost::system::error_code error;
    stream.handshake(dial.sni.empty() ? dial.host : dial.sni, dial.path, error);
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
        result.error = upgrade(*stream, dial);
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
    result.error = upgrade(*stream, dial);
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
void exchange(Stream& stream, const SocketDial& dial, const std::string& body, Probe& probe)
{
    bhttp::request<bhttp::string_body> out{
        body.empty() ? bhttp::verb::get : bhttp::verb::post, dial.path, 11};
    out.set(bhttp::field::host, dial.sni.empty() ? dial.host : dial.sni);
    for (const auto& [name, value] : dial.headers) {
        out.set(name, value);
    }
    out.body() = body;
    out.prepare_payload();

    boost::system::error_code error;
    beast::get_lowest_layer(stream).expires_after(dial.connectTimeout);
    bhttp::write(stream, out, error);
    if (error) {
        probe.error = "the request would not go: " + error.message();
        return;
    }
    beast::flat_buffer buffer;
    bhttp::response<bhttp::string_body> in;
    bhttp::read(stream, buffer, in, error);
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
        exchange(*connected.plain, dial, body, probe);
        return probe;
    }
    exchange(*connected.secure, dial, body, probe);
    boost::system::error_code ignored;
    connected.secure->shutdown(ignored);
    return probe;
}

}  // namespace bazarish::http
