// Bazarish project (c) 2026
#include "bazarish/HttpServer.hpp"
#include "bazarish/WebSocket.hpp"
#include "bazarish/WebSocketClient.hpp"

#include "TestUtil.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
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

constexpr const char* kLoopback = "127.0.0.1";
constexpr const char* kPath = "/keep";
constexpr std::chrono::seconds kSilence{1};
constexpr std::chrono::seconds kPongWait{1};
constexpr std::chrono::seconds kServerSilence{2};
constexpr std::chrono::milliseconds kBusyEvery{300};
constexpr std::chrono::seconds kBusyFor{3};
constexpr std::chrono::milliseconds kQuietFor{3500};
constexpr std::chrono::seconds kWatchFor{3};
constexpr std::chrono::seconds kPatience{10};
constexpr int kLeastQuietPings = 2;
const std::string kPayload = "x";

SocketDial dialTo(const int port)
{
    SocketDial dial;
    dial.host = kLoopback;
    dial.port = port;
    dial.path = kPath;
    dial.tls = false;
    dial.pingAfterSilence = kSilence;
    dial.pongTimeout = kPongWait;
    dial.pingPayload = []() { return kPayload; };
    return dial;
}

struct Heard {
    std::mutex mutex;
    std::vector<std::string> pings;
    std::atomic<int> messages{0};

    std::size_t pingCount()
    {
        const std::lock_guard<std::mutex> lock(mutex);
        return pings.size();
    }
};

// A raw client that never pings; it counts the pings it is sent and when its socket ends.
struct RawWatch {
    int pings = 0;
    bool ended = false;
};

RawWatch watchRaw(const int port, const std::chrono::seconds span)
{
    asio::io_context io;
    tcp::socket socket(io);
    socket.connect(tcp::endpoint(asio::ip::make_address(kLoopback),
        static_cast<unsigned short>(port)));
    websocket::stream<tcp::socket> stream(std::move(socket));
    stream.handshake(kLoopback, kPath);
    RawWatch watch;
    stream.control_callback([&watch](const websocket::frame_type kind, const beast::string_view) {
        if (kind == websocket::frame_type::ping) {
            ++watch.pings;
        }
    });
    beast::flat_buffer buffer;
    stream.async_read(buffer, [&watch](const boost::system::error_code& error, std::size_t) {
        watch.ended = static_cast<bool>(error);
    });
    io.run_for(span);
    return watch;
}

void checkPingsOnlyAfterSilence()
{
    Server::Options options;
    options.port = 0;
    Server server(options);
    Heard heard;
    SocketRoutes routes;
    routes.silenceLimit = kServerSilence;
    routes.message = [&heard](const SocketPtr& socket, const std::vector<unsigned char>& message) {
        ++heard.messages;
        socket->send(message);
    };
    routes.pinged = [&heard](const SocketPtr&, const std::string& payload) {
        const std::lock_guard<std::mutex> lock(heard.mutex);
        heard.pings.push_back(payload);
    };
    server.upgrade(kPath, routes);
    const int port = server.start();
    CHECK(port > 0);

    std::atomic<bool> closed{false};
    const SocketDialResult dialled = openSocket(dialTo(port),
        [](const SocketPtr&, const std::vector<unsigned char>&) {},
        [&closed](const SocketPtr&) { closed = true; });
    CHECK(dialled.socket != nullptr);
    const std::vector<unsigned char> note = {1, 2, 3};
    const auto busyUntil = std::chrono::steady_clock::now() + kBusyFor;
    while (std::chrono::steady_clock::now() < busyUntil) {
        dialled.socket->send(note);
        std::this_thread::sleep_for(kBusyEvery);
    }
    CHECK(heard.messages.load() > 1);
    CHECK(heard.pingCount() == 0);

    std::this_thread::sleep_for(kQuietFor);
    CHECK(heard.pingCount() >= static_cast<std::size_t>(kLeastQuietPings));
    {
        const std::lock_guard<std::mutex> lock(heard.mutex);
        for (const std::string& payload : heard.pings) {
            CHECK(payload == kPayload);
        }
    }
    CHECK(dialled.socket->open());
    CHECK(!closed.load());
    dialled.socket->close();

    const RawWatch quiet = watchRaw(port, kWatchFor);
    CHECK(quiet.pings == 0);
    CHECK(quiet.ended);
    server.stop();

    Server pinging(options);
    SocketRoutes beastRoutes;
    beastRoutes.idleTimeout = kServerSilence;
    pinging.upgrade(kPath, beastRoutes);
    const int pingingPort = pinging.start();
    CHECK(pingingPort > 0);
    const RawWatch pinged = watchRaw(pingingPort, kWatchFor);
    CHECK(pinged.pings > 0);
    pinging.stop();
}

void checkDeadLinkEnds()
{
    asio::io_context io;
    tcp::acceptor door(io, tcp::endpoint(asio::ip::make_address(kLoopback), 0));
    const int port = door.local_endpoint().port();
    std::atomic<bool> accepted{false};
    std::atomic<bool> closed{false};
    std::thread deaf([&door, &accepted, &closed]() {
        tcp::socket taken = door.accept();
        websocket::stream<tcp::socket> stream(std::move(taken));
        stream.accept();
        accepted = true;
        CHECK(testutil::waitFor([&closed]() { return closed.load(); }, kPatience));
    });

    const auto started = std::chrono::steady_clock::now();
    const SocketDialResult dialled = openSocket(dialTo(port),
        [](const SocketPtr&, const std::vector<unsigned char>&) {},
        [&closed](const SocketPtr&) { closed = true; });
    CHECK(dialled.socket != nullptr);
    CHECK(testutil::waitFor([&closed]() { return closed.load(); }));
    const auto took = std::chrono::steady_clock::now() - started;
    CHECK(took >= kSilence + kPongWait);
    CHECK(took < kPatience);
    CHECK(accepted.load());
    deaf.join();
}

}  // namespace

int main()
{
    checkPingsOnlyAfterSilence();
    checkDeadLinkEnds();
    std::printf("TestSocketKeepalive ok\n");
    return 0;
}
