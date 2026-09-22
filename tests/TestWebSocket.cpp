// Bazarish project (c) 2026
#include "bazarish/WebSocket.hpp"

#include "TestUtil.hpp"

#include <utility>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = boost::beast::websocket;
using asio::ip::tcp;
using namespace bazarish;
using namespace bazarish::http;

namespace {

constexpr const char* kPath = "/socket";
constexpr const char* kProtocol = "test/1";
constexpr const char* kTokenHeader = "x-test-token";
constexpr const char* kToken = "the-token";

std::string text(const std::vector<unsigned char>& data)
{
    return std::string(data.begin(), data.end());
}

// Everything the handlers saw, so the test can wait for it rather than sleep
// for it: a test that sleeps is a test that is flaky on a loaded machine.
struct Seen {
    std::mutex mutex;
    std::condition_variable changed;
    int opened = 0;
    int closed = 0;
    std::vector<std::string> messages;
    std::string protocolHeader;

    void note(const std::function<void()>& change)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex);
            change();
        }
        changed.notify_all();
    }

    bool waitFor(const std::function<bool()>& done)
    {
        std::unique_lock<std::mutex> lock(mutex);
        return changed.wait_for(lock, std::chrono::seconds(10), done);
    }
};

// Opens a socket to the server, or reports how it was refused.
struct Dialled {
    std::unique_ptr<websocket::stream<tcp::socket>> socket;
    unsigned refusedWith = 0;
    std::string negotiated;
};

Dialled dial(asio::io_context& io, const int port, const std::string& path,
    const std::string& token)
{
    tcp::socket raw(io);
    raw.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"),
        static_cast<unsigned short>(port)));
    auto stream = std::make_unique<websocket::stream<tcp::socket>>(std::move(raw));
    stream->set_option(websocket::stream_base::decorator(
        [token](websocket::request_type& request) {
            request.set(kTokenHeader, token);
            request.set(boost::beast::http::field::sec_websocket_protocol, kProtocol);
        }));
    websocket::response_type response;
    boost::system::error_code error;
    stream->handshake(response, "127.0.0.1", path, error);
    Dialled out;
    if (error) {
        out.refusedWith = static_cast<unsigned>(response.result_int());
        return out;
    }
    out.negotiated = std::string(response[boost::beast::http::field::sec_websocket_protocol]);
    out.socket = std::move(stream);
    return out;
}

}  // namespace

int main()
{
    Seen seen;
    Server::Options options;
    options.port = 0;
    Server server(options);

    SocketRoutes routes;
    routes.subprotocol = kProtocol;
    routes.maxMessageBytes = 4096;
    // An unauthorised upgrade is refused with an ordinary response, which is how
    // it becomes the same 404 as everything else on a host.
    routes.admit = [](const Request& request) -> std::optional<Response> {
        if (request.header(kTokenHeader) != kToken) {
            return Response{404, "text/html", {}, "<html>nothing here</html>"};
        }
        return std::nullopt;
    };
    routes.opened = [&seen](const SocketPtr&, const Request& request) {
        seen.note([&]() {
            ++seen.opened;
            seen.protocolHeader = request.header("sec-websocket-protocol");
        });
    };
    routes.message = [&seen](const SocketPtr& socket, const std::vector<unsigned char>& message) {
        seen.note([&]() { seen.messages.push_back(text(message)); });
        // Answer with the same bytes turned round, so the test proves the
        // payload survived rather than that something arrived.
        std::vector<unsigned char> reply(message.rbegin(), message.rend());
        socket->send(std::move(reply));
    };
    routes.closed = [&seen](const SocketPtr&) { seen.note([&]() { ++seen.closed; }); };
    server.upgrade(kPath, routes);
    server.get("/plain", [](const Request&) {
        return Response{200, "text/plain", {}, "ordinary"};
    });

    const int port = server.start();
    CHECK(port > 0);

    asio::io_context io;

    // An upgrade with no token is refused, and refused as a page rather than as
    // a protocol error: the client learns nothing about what is here.
    const Dialled unauthorised = dial(io, port, kPath, "wrong");
    CHECK(unauthorised.socket == nullptr);
    CHECK(unauthorised.refusedWith == 404);

    // An upgrade at a path nobody serves is the ordinary 404 of a path nobody
    // serves: asking for a socket does not make a host answer differently.
    const Dialled nowhere = dial(io, port, "/nothing", kToken);
    CHECK(nowhere.socket == nullptr);
    CHECK(nowhere.refusedWith == 404);

    // An upgrade at a path that has an ordinary route falls through to it and
    // is answered as the request it also is.
    const Dialled elsewhere = dial(io, port, "/plain", kToken);
    CHECK(elsewhere.socket == nullptr);
    CHECK(elsewhere.refusedWith == 200);

    // An authorised upgrade opens, and the protocol the client named comes back.
    Dialled dialled = dial(io, port, kPath, kToken);
    CHECK(dialled.socket != nullptr);
    CHECK(dialled.negotiated == kProtocol);
    CHECK(seen.waitFor([&]() { return seen.opened == 1; }));
    CHECK(seen.protocolHeader == kProtocol);

    // Binary in, binary out, payload intact.
    dialled.socket->binary(true);
    dialled.socket->write(asio::buffer(std::string("hello")));
    CHECK(seen.waitFor([&]() { return seen.messages.size() == 1; }));
    CHECK(seen.messages.front() == "hello");
    beast::flat_buffer buffer;
    dialled.socket->read(buffer);
    CHECK(dialled.socket->got_binary());
    CHECK(beast::buffers_to_string(buffer.data()) == "olleh");

    // Several messages keep their order, because a queue that reorders is a
    // stream that corrupts.
    buffer.consume(buffer.size());
    for (int i = 0; i < 8; ++i) {
        const std::string message = "message-" + std::to_string(i);
        dialled.socket->write(asio::buffer(message));
    }
    for (int i = 0; i < 8; ++i) {
        beast::flat_buffer reply;
        dialled.socket->read(reply);
        const std::string got = beast::buffers_to_string(reply.data());
        const std::string sent = "message-" + std::to_string(i);
        CHECK(got == std::string(sent.rbegin(), sent.rend()));
    }

    // Closing from the client end is noticed once.
    boost::system::error_code ignored;
    dialled.socket->close(websocket::close_code::normal, ignored);
    CHECK(seen.waitFor([&]() { return seen.closed == 1; }));

    // A text frame is not tolerated: a caller sending one is not speaking this
    // protocol, and the socket ends rather than guessing what was meant.
    Dialled talker = dial(io, port, kPath, kToken);
    CHECK(talker.socket != nullptr);
    CHECK(seen.waitFor([&]() { return seen.opened == 2; }));
    talker.socket->text(true);
    talker.socket->write(asio::buffer(std::string("words")));
    CHECK(seen.waitFor([&]() { return seen.closed == 2; }));
    talker.socket->close(websocket::close_code::normal, ignored);

    // The server sends of its own accord, and the client hears it.
    Dialled listener = dial(io, port, kPath, kToken);
    CHECK(listener.socket != nullptr);
    CHECK(seen.waitFor([&]() { return seen.opened == 3; }));
    listener.socket->binary(true);
    listener.socket->write(asio::buffer(std::string("ping")));
    beast::flat_buffer unsolicited;
    listener.socket->read(unsolicited);
    CHECK(beast::buffers_to_string(unsolicited.data()) == "gnip");
    listener.socket->close(websocket::close_code::normal, ignored);
    CHECK(seen.waitFor([&]() { return seen.closed == 3; }));

    server.stop();
    std::printf("TestWebSocket ok\n");
    return 0;
}
