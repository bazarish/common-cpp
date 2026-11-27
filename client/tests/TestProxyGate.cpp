// Bazarish project (c) 2026
#include "I2pRouter.hpp"
#include "TestUtil.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <thread>

namespace asio = boost::asio;
using bazarish::client::ProxyUnreachable;

namespace {

constexpr const char* kLoopback = "127.0.0.1";

class NonSocksListener {
public:
    NonSocksListener()
        : acceptor_(io_, asio::ip::tcp::endpoint(asio::ip::make_address(kLoopback), 0))
    {
        accept();
        thread_ = std::thread([this]() { io_.run(); });
    }

    NonSocksListener(const NonSocksListener&) = delete;
    NonSocksListener& operator=(const NonSocksListener&) = delete;

    ~NonSocksListener()
    {
        io_.stop();
        thread_.join();
    }

    int port() const { return acceptor_.local_endpoint().port(); }
    int taken() const { return taken_.load(); }

private:
    void accept()
    {
        acceptor_.async_accept([this](const boost::system::error_code& error, asio::ip::tcp::socket socket) {
            if (error) {
                return;
            }
            ++taken_;
            boost::system::error_code ignored;
            socket.close(ignored);
            accept();
        });
    }

    asio::io_context io_;
    asio::ip::tcp::acceptor acceptor_;
    std::atomic<int> taken_{0};
    std::thread thread_;
};

}  // namespace

int main()
try {
    const testutil::ScratchDir scratch("proxy-gate");
    NonSocksListener proxy;
    bazarish::client::setI2pSocksProxy(kLoopback, proxy.port());

    CHECK(!bazarish::client::i2pProxyUnreachable());
    CHECK_THROWS(bazarish::client::sharedI2pRouter(scratch.path()));
    CHECK(proxy.taken() == 1);
    CHECK(bazarish::client::i2pProxyUnreachable());
    CHECK(!bazarish::client::sharedI2pRouterIfRunning().has_value());
    CHECK(!std::filesystem::exists(scratch.path() / "netDb"));

    bool unreachable = false;
    try {
        bazarish::client::sharedI2pRouter(scratch.path());
    } catch (const ProxyUnreachable&) {
        unreachable = true;
    }
    CHECK(unreachable);
    CHECK(proxy.taken() == 1);

    bazarish::client::setI2pSocksProxy(kLoopback, proxy.port());
    CHECK(!bazarish::client::i2pProxyUnreachable());
    CHECK_THROWS(bazarish::client::sharedI2pRouter(scratch.path()));
    CHECK(proxy.taken() == 2);

    std::fprintf(stderr, "TestProxyGate passed\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
