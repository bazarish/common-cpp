// Bazarish project (c) 2026
#include "SocksProxy.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/tcp_stream.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>

namespace bazarish::client {

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
using asio::ip::tcp;

// RFC 1928, section 3.
constexpr std::uint8_t kSocks5 = 0x05;
constexpr std::uint8_t kOneMethod = 1;
constexpr std::uint8_t kNoAuthentication = 0x00;
constexpr std::uint8_t kNoAcceptableMethods = 0xFF;
constexpr std::array kGreeting{kSocks5, kOneMethod, kNoAuthentication};
constexpr std::size_t kMethodReplySize = 2;

constexpr std::chrono::seconds kCheckTimeout{10};

SocksAnswer verdict(const std::array<std::uint8_t, kMethodReplySize>& reply)
{
    if (reply[0] != kSocks5) {
        return SocksAnswer::eNotSocks5;
    }
    if (reply[1] == kNoAuthentication) {
        return SocksAnswer::eAccepted;
    }
    if (reply[1] == kNoAcceptableMethods) {
        return SocksAnswer::eNeedsAuthentication;
    }
    return SocksAnswer::eNotSocks5;
}

asio::awaitable<SocksCheck> greet(const std::string host, const int port)
{
    SocksCheck check;
    const asio::any_io_executor executor = co_await asio::this_coro::executor;
    boost::system::error_code error;

    tcp::resolver resolver(executor);
    const tcp::resolver::results_type found = co_await resolver.async_resolve(
        host, std::to_string(port), asio::redirect_error(asio::use_awaitable, error));
    if (error) {
        check.error = "cannot find " + host + ": " + error.message();
        co_return check;
    }

    beast::tcp_stream stream(executor);
    stream.expires_after(kCheckTimeout);
    co_await stream.async_connect(found, asio::redirect_error(asio::use_awaitable, error));
    if (error) {
        check.error = "cannot reach " + host + ": " + error.message();
        co_return check;
    }

    check.answer = SocksAnswer::eNotSocks5;
    co_await asio::async_write(
        stream, asio::buffer(kGreeting), asio::redirect_error(asio::use_awaitable, error));
    if (error) {
        check.error = "the greeting would not go: " + error.message();
        co_return check;
    }
    std::array<std::uint8_t, kMethodReplySize> reply{};
    co_await asio::async_read(
        stream, asio::buffer(reply), asio::redirect_error(asio::use_awaitable, error));
    if (error) {
        check.error = "no answer to the greeting: " + error.message();
        co_return check;
    }
    check.answer = verdict(reply);
    co_return check;
}

}  // namespace

SocksCheck checkSocksProxy(const std::string& host, const int port)
{
    asio::io_context loop;
    std::future<SocksCheck> check = asio::co_spawn(loop, greet(host, port), asio::use_future);
    loop.run();
    return check.get();
}

}  // namespace bazarish::client
