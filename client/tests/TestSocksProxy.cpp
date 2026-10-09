// Bazarish project (c) 2026
#include "SocksProxy.hpp"

#include "TestUtil.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <cstddef>
#include <cstdio>
#include <string>
#include <thread>
#include <utility>

namespace asio = boost::asio;
using asio::ip::tcp;
using namespace bazarish::client;

namespace {

constexpr const char* kLoopback = "127.0.0.1";

// RFC 1928, section 3.
constexpr std::size_t kGreetingSize = 3;
constexpr char kSocks5 = 0x05;
constexpr char kNoAuthentication = 0x00;
constexpr char kNoAcceptableMethods = static_cast<char>(0xFF);

class OneAnswer {
public:
    explicit OneAnswer(std::string reply)
        : acceptor_(loop_, tcp::endpoint(asio::ip::make_address(kLoopback), 0))
        , thread_([this, reply = std::move(reply)]() { answer(reply); })
    {
    }

    ~OneAnswer() { thread_.join(); }

    int port() const { return acceptor_.local_endpoint().port(); }

private:
    void answer(const std::string& reply)
    {
        tcp::socket peer = acceptor_.accept();
        std::array<char, kGreetingSize> greeting{};
        CHECK(asio::read(peer, asio::buffer(greeting)) == kGreetingSize);
        CHECK(asio::write(peer, asio::buffer(reply)) == reply.size());
    }

    asio::io_context loop_;
    tcp::acceptor acceptor_;
    std::thread thread_;
};

int closedPort()
{
    asio::io_context loop;
    const tcp::acceptor taken(loop, tcp::endpoint(asio::ip::make_address(kLoopback), 0));
    return taken.local_endpoint().port();
}

}  // namespace

int main()
{
    {
        OneAnswer proxy(std::string{kSocks5, kNoAuthentication});
        const SocksCheck check = checkSocksProxy(kLoopback, proxy.port());
        CHECK(check.answer == SocksAnswer::eAccepted);
        CHECK(check.error.empty());
    }
    {
        OneAnswer proxy(std::string{kSocks5, kNoAcceptableMethods});
        CHECK(checkSocksProxy(kLoopback, proxy.port()).answer
            == SocksAnswer::eNeedsAuthentication);
    }
    {
        OneAnswer proxy("HTTP/1.1 400 Bad Request\r\n\r\n");
        CHECK(checkSocksProxy(kLoopback, proxy.port()).answer == SocksAnswer::eNotSocks5);
    }
    {
        OneAnswer proxy("");
        const SocksCheck check = checkSocksProxy(kLoopback, proxy.port());
        CHECK(check.answer == SocksAnswer::eNotSocks5);
        CHECK(!check.error.empty());
    }
    {
        const SocksCheck check = checkSocksProxy(kLoopback, closedPort());
        CHECK(check.answer == SocksAnswer::eUnreachable);
        CHECK(!check.error.empty());
    }

    std::printf("TestSocksProxy ok\n");
    return 0;
}
