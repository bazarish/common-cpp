// Bazarish project (c) 2026
#include "bazarish/WebSocketClient.hpp"

#include "bazarish/Tls.hpp"
#include "bazarish/WebSocket.hpp"
#include "TestUtil.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::http;

namespace {

constexpr const char* kLoopback = "127.0.0.1";
constexpr const char* kPath = "/duplex";
constexpr const char* kProtocol = "test/1";
constexpr int kMessages = 20000;
constexpr std::size_t kMessageBytes = 4096;
constexpr int kPatienceSeconds = 60;
constexpr std::size_t kPumpBytes = 16384;
constexpr int kPollMs = 100;

int loopbackSocket(const int port, const bool listening)
{
    const int handle = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(handle >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = ::inet_addr(kLoopback);
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    if (listening) {
        CHECK(::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0);
        CHECK(::listen(handle, 1) == 0);
    } else {
        CHECK(::connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0);
    }
    return handle;
}

// What sits in front of a gateway in a deployment: TLS on the outside, plain behind.
class TlsFront {
public:
    TlsFront(const tls::Credential& credential, const int to)
        : to_(to)
    {
        context_ = SSL_CTX_new(TLS_server_method());
        CHECK(context_ != nullptr);
        CHECK(SSL_CTX_use_certificate_chain_file(context_, credential.certificate.c_str()) == 1);
        CHECK(SSL_CTX_use_PrivateKey_file(context_, credential.key.c_str(), SSL_FILETYPE_PEM)
            == 1);
        listen_ = loopbackSocket(0, true);
        sockaddr_in address{};
        socklen_t length = sizeof address;
        CHECK(::getsockname(listen_, reinterpret_cast<sockaddr*>(&address), &length) == 0);
        port_ = ntohs(address.sin_port);
        thread_ = std::thread([this]() { serve(); });
    }

    ~TlsFront()
    {
        running_.store(false);
        ::shutdown(listen_, SHUT_RDWR);
        ::close(listen_);
        thread_.join();
        SSL_CTX_free(context_);
    }

    int port() const { return port_; }

private:
    void serve()
    {
        const int in = ::accept(listen_, nullptr, nullptr);
        if (in < 0) {
            return;
        }
        SSL* const session = SSL_new(context_);
        CHECK(SSL_set_fd(session, in) == 1);
        if (SSL_accept(session) == 1) {
            pump(session, in, loopbackSocket(to_, false));
        }
        SSL_free(session);
        ::close(in);
    }

    void pump(SSL* const session, const int in, const int out)
    {
        std::vector<char> buffer(kPumpBytes);
        while (running_.load()) {
            pollfd watched[2] = {{in, POLLIN, 0}, {out, POLLIN, 0}};
            if (SSL_pending(session) == 0 && ::poll(watched, 2, kPollMs) <= 0) {
                continue;
            }
            if (SSL_pending(session) > 0 || (watched[0].revents & POLLIN) != 0) {
                const int got = SSL_read(session, buffer.data(), static_cast<int>(buffer.size()));
                if (got <= 0 || ::send(out, buffer.data(), static_cast<std::size_t>(got),
                                    MSG_NOSIGNAL) != got) {
                    break;
                }
            }
            if ((watched[1].revents & POLLIN) != 0) {
                const ssize_t got = ::recv(out, buffer.data(), buffer.size(), 0);
                if (got <= 0 || SSL_write(session, buffer.data(), static_cast<int>(got)) != got) {
                    break;
                }
            }
        }
        ::close(out);
    }

    int to_;
    SSL_CTX* context_ = nullptr;
    int listen_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::thread thread_;
};

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-ws-tls-duplex-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    const tls::Credential credential = tls::selfSigned(root);

    Server::Options options;
    options.host = kLoopback;
    options.port = 0;
    Server server(options);
    SocketRoutes routes;
    routes.subprotocol = kProtocol;
    routes.maxMessageBytes = 2 * kMessageBytes;
    routes.message = [](const SocketPtr& socket, const std::vector<unsigned char>& message) {
        socket->send(message);
    };
    server.upgrade(kPath, routes);
    const int port = server.start();
    CHECK(port > 0);
    const TlsFront front(credential, port);

    std::mutex mutex;
    std::condition_variable changed;
    int echoed = 0;
    bool intact = true;
    bool lost = false;

    SocketDial dial;
    dial.host = kLoopback;
    dial.port = front.port();
    dial.path = kPath;
    dial.tls = true;
    dial.pin = credential.pin;
    dial.subprotocol = kProtocol;
    dial.maxMessageBytes = 2 * kMessageBytes;
    const SocketDialResult dialled = openSocket(dial,
        [&](const SocketPtr&, const std::vector<unsigned char>& message) {
            {
                const std::lock_guard<std::mutex> lock(mutex);
                const unsigned char expected = static_cast<unsigned char>(echoed);
                intact = intact && message.size() == kMessageBytes && message.front() == expected
                    && message.back() == expected;
                ++echoed;
            }
            changed.notify_all();
        },
        [&](const SocketPtr&) {
            {
                const std::lock_guard<std::mutex> lock(mutex);
                lost = true;
            }
            changed.notify_all();
        });
    CHECK(dialled.socket != nullptr);

    for (int sent = 0; sent < kMessages; ++sent) {
        dialled.socket->send(
            std::vector<unsigned char>(kMessageBytes, static_cast<unsigned char>(sent)));
    }
    bool done = false;
    {
        std::unique_lock<std::mutex> lock(mutex);
        done = changed.wait_for(lock, std::chrono::seconds(kPatienceSeconds),
            [&]() { return echoed == kMessages || lost; });
        std::fprintf(stderr, "echoed %d of %d, intact %d, lost %d\n", echoed, kMessages,
            intact ? 1 : 0, lost ? 1 : 0);
        done = done && echoed == kMessages && intact && !lost;
    }
    CHECK(done);

    dialled.socket->close();
    server.stop();
    std::filesystem::remove_all(root);
    std::printf("TestWebSocketTlsDuplex ok\n");
    return 0;
}
