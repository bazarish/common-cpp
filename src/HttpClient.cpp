// Bazarish project (c) 2026
#include <bazarish/HttpClient.hpp>

#include <bazarish/Log.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

namespace bazarish::http {

namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace beasthttp = boost::beast::http;
using asio::ip::tcp;
}  // namespace

asio::awaitable<Response> fetch(asio::any_io_executor executor, const std::string& host,
    const int port, ClientRequest request, const std::chrono::seconds timeout)
{
    Response answer;
    try {
        tcp::resolver resolver(executor);
        beast::tcp_stream stream(executor);
        const auto endpoints = co_await resolver.async_resolve(
            host, std::to_string(port), asio::use_awaitable);
        stream.expires_after(timeout);
        co_await stream.async_connect(endpoints, asio::use_awaitable);

        beasthttp::request<beasthttp::string_body> out{
            beasthttp::string_to_verb(request.method), request.target, 11};
        out.set(beasthttp::field::host, host);
        for (const auto& header : request.headers) {
            out.set(header.first, header.second);
        }
        out.body() = request.body;
        out.prepare_payload();
        stream.expires_after(timeout);
        co_await beasthttp::async_write(stream, out, asio::use_awaitable);

        beast::flat_buffer buffer;
        beasthttp::response<beasthttp::string_body> in;
        stream.expires_after(timeout);
        co_await beasthttp::async_read(stream, buffer, in, asio::use_awaitable);

        answer.status = static_cast<int>(in.result_int());
        answer.body = in.body();
        if (in.count(beasthttp::field::content_type) > 0) {
            answer.contentType = std::string(in[beasthttp::field::content_type]);
        }
        boost::system::error_code ignored;
        stream.socket().shutdown(tcp::socket::shutdown_both, ignored);
    } catch (const std::exception& error) {
        // Status 0 is "the backend did not answer", which the caller turns into a
        // gateway failure - not a protocol error of its own.
        bazarish::log::warn("upstream {}:{} failed: {}", host, port, error.what());
        answer.status = 0;
    }
    co_return answer;
}

}  // namespace bazarish::http
