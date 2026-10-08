// Bazarish project (c) 2026
#include "bazarish/WebSocketClient.hpp"

#include "bazarish/WebSocket.hpp"
#include "TestUtil.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace asio = boost::asio;
using asio::ip::tcp;
using namespace bazarish;
using namespace bazarish::http;

namespace {

constexpr const char* kLoopback = "127.0.0.1";
constexpr const char* kPath = "/socket";
constexpr const char* kProtocol = "test/1";
constexpr int kDeadlineSeconds = 1;
constexpr int kPatienceSeconds = 10;

// Accepts and then says nothing: what a silent peer looks like to a dial.
class MuteListener {
public:
    MuteListener()
        : acceptor_(loop_, tcp::endpoint(asio::ip::make_address(kLoopback), 0))
    {
        take();
        thread_ = std::thread([this]() { loop_.run(); });
    }

    ~MuteListener()
    {
        loop_.stop();
        thread_.join();
    }

    int port() const { return acceptor_.local_endpoint().port(); }

private:
    void take()
    {
        acceptor_.async_accept([this](const boost::system::error_code& error, tcp::socket taken) {
            if (error) {
                return;
            }
            held_.push_back(std::move(taken));
            take();
        });
    }

    asio::io_context loop_;
    tcp::acceptor acceptor_;
    std::thread thread_;
    std::vector<tcp::socket> held_;
};

SocketDial dialTo(const int port)
{
    SocketDial dial;
    dial.host = kLoopback;
    dial.port = port;
    dial.path = kPath;
    dial.tls = false;
    dial.subprotocol = kProtocol;
    dial.connectTimeout = std::chrono::seconds(kDeadlineSeconds);
    return dial;
}

int secondsTaken(const std::function<void()>& work)
{
    const auto started = std::chrono::steady_clock::now();
    work();
    return static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - started)
                                .count());
}

}  // namespace

int main()
{
    {
        MuteListener mute;
        Probe probe;
        const int probeTook
            = secondsTaken([&]() { probe = probeHost(dialTo(mute.port()), "a question"); });
        CHECK(!probe.reached);
        CHECK(!probe.error.empty());
        CHECK(probeTook < kPatienceSeconds);

        SocketDialResult dialled;
        const int dialTook = secondsTaken([&]() {
            dialled = openSocket(
                dialTo(mute.port()), [](const SocketPtr&, const std::vector<unsigned char>&) {},
                [](const SocketPtr&) {});
        });
        CHECK(dialled.socket == nullptr);
        CHECK(!dialled.error.empty());
        CHECK(dialTook < kPatienceSeconds);
    }

    {
        Server::Options options;
        options.port = 0;
        Server server(options);

        std::mutex mutex;
        std::condition_variable changed;
        std::vector<std::string> echoed;

        SocketRoutes routes;
        routes.subprotocol = kProtocol;
        routes.message = [](const SocketPtr& socket, const std::vector<unsigned char>& message) {
            socket->send(std::vector<unsigned char>(message.rbegin(), message.rend()));
        };
        server.upgrade(kPath, routes);
        server.post("/answer", [](const Request&) {
            return Response{200, "text/plain", {}, "here"};
        });

        const int port = server.start();
        CHECK(port > 0);

        SocketDial dial = dialTo(port);
        dial.path = "/answer";
        const Probe probe = probeHost(dial, "a question");
        CHECK(probe.reached);
        CHECK(probe.status == 200);
        CHECK(probe.error.empty());

        const SocketDialResult dialled = openSocket(dialTo(port),
            [&](const SocketPtr&, const std::vector<unsigned char>& message) {
                {
                    const std::lock_guard<std::mutex> lock(mutex);
                    echoed.push_back(std::string(message.begin(), message.end()));
                }
                changed.notify_all();
            },
            [](const SocketPtr&) {});
        CHECK(dialled.error.empty());
        CHECK(dialled.socket != nullptr);

        const std::string sent = "hello";
        dialled.socket->send(std::vector<unsigned char>(sent.begin(), sent.end()));
        {
            std::unique_lock<std::mutex> lock(mutex);
            CHECK(changed.wait_for(lock, std::chrono::seconds(kPatienceSeconds),
                [&]() { return !echoed.empty(); }));
            CHECK(echoed.front() == std::string(sent.rbegin(), sent.rend()));
        }
        dialled.socket->close();
        server.stop();
    }

    std::printf("TestWebSocketClient ok\n");
    return 0;
}
