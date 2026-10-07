// Bazarish project (c) 2026
#include "bazarish/I2pHttp.hpp"

#include "TestUtil.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <exception>
#include <string>
#include <sys/types.h>

using namespace bazarish;

namespace {

class FdStream {
public:
    explicit FdStream(int fd) : fd_(fd) {}
    FdStream(FdStream&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    ~FdStream() { if (fd_ >= 0) { ::close(fd_); } }
    FdStream(const FdStream&) = delete;
    FdStream& operator=(const FdStream&) = delete;

    std::size_t readSome(void* buffer, std::size_t size)
    {
        const ssize_t n = ::read(fd_, buffer, size);
        return n > 0 ? static_cast<std::size_t>(n) : 0;
    }

private:
    int fd_;
};

FdStream streamFrom(const std::string& data)
{
    int fds[2] = {-1, -1};
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    CHECK(::write(fds[1], data.data(), data.size()) == static_cast<ssize_t>(data.size()));
    CHECK(::close(fds[1]) == 0);
    return FdStream(fds[0]);
}

constexpr std::size_t kSomeBodyBound = 64 * 1024;

}  // namespace

int main()
{
    {
        const std::string get
            = buildI2pHttpRequest("GET", "h.b32.i2p", "/b/x", {{"Range", "bytes=10-"}}, 0);
        CHECK(get
            == "GET /b/x HTTP/1.1\r\nHost: h.b32.i2p\r\n"
               "Range: bytes=10-\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        const std::string post
            = buildI2pHttpRequest("POST", "h.b32.i2p", "/b/x/confirm", {}, 42);
        CHECK(post
            == "POST /b/x/confirm HTTP/1.1\r\nHost: h.b32.i2p\r\n"
               "Content-Length: 42\r\nConnection: close\r\n\r\n");
    }

    {
        CHECK(parseI2pHttpStatus("HTTP/1.1 200 OK") == 200);
        CHECK(parseI2pHttpStatus("HTTP/1.1 404 Not Found") == 404);
        CHECK_THROWS(parseI2pHttpStatus("garbage-no-space"));
    }

    {
        const std::map<std::string, std::string> headers = parseI2pHttpHeaders(
            "HTTP/1.1 206 Partial Content\r\n"
            "Content-Length:  123\r\n"
            "Content-Range: bytes 10-132/200\r\n"
            "X-Blob-Total:\t77\r\n"
            "junk-line-without-colon");
        CHECK(headers.at("content-length") == "123");
        CHECK(headers.at("content-range") == "bytes 10-132/200");
        CHECK(headers.at("x-blob-total") == "77");
        CHECK(headers.find("junk-line-without-colon") == headers.end());
    }

    {
        FdStream stream
            = streamFrom("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
        const I2pHttpResponse response = readI2pHttpResponse(stream, kSomeBodyBound);
        CHECK(response.status == 200);
        CHECK(response.headers.at("content-length") == "5");
        CHECK(response.body == "hello");
    }

    {
        FdStream stream
            = streamFrom("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot-found");
        const I2pHttpHead head = readI2pHttpHead(stream);
        CHECK(head.status == 404);
        CHECK(head.headers.at("content-length") == "9");
        CHECK(head.leftover == "not-found");
    }

    {
        FdStream stream = streamFrom("HTTP/1.1 200 OK\r\nContent-Len");
        std::string said;
        try {
            (void)readI2pHttpHead(stream);
        } catch (const std::exception& error) {
            said = error.what();
        }
        CHECK(said.find("closed after 28 bytes") != std::string::npos);
    }

    {
        FdStream stream = streamFrom("HTTP/1.1 200 OK\r\n\r\n");
        const I2pHttpResponse response = readI2pHttpResponse(stream, kSomeBodyBound);
        CHECK(response.status == 200);
        CHECK(response.body.empty());
    }

    {
        FdStream stream = streamFrom("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n");
        CHECK_THROWS(readI2pHttpResponse(stream, 10));
    }

    {
        FdStream stream = streamFrom("HTTP/1.1 200 OK\r\n\r\n0123456789abc");
        CHECK_THROWS(readI2pHttpResponse(stream, 10));
    }

    {
        FdStream stream
            = streamFrom("HTTP/1.1 200 OK\r\nX: " + std::string(kMaxI2pHttpHeadBytes, 'y'));
        std::string said;
        try {
            (void)readI2pHttpHead(stream);
        } catch (const std::exception& error) {
            said = error.what();
        }
        CHECK(said.find("head is over") != std::string::npos);
    }

    {
        FdStream stream = streamFrom("GET /hello HTTP/1.1\r\nHost: h.b32.i2p\r\n"
                                     "X-Bazarish-Pair: 1234\r\n\r\nleft");
        const I2pHttpRequestHead head = readI2pHttpRequestHead(stream);
        CHECK(head.method == "GET");
        CHECK(head.target == "/hello");
        CHECK(head.headers.at("x-bazarish-pair") == "1234");
        CHECK(head.headers.at("host") == "h.b32.i2p");
        CHECK(head.leftover == "left");
    }

    {
        const I2pHttpRequestLine line = parseI2pHttpRequestLine("POST /a/b HTTP/1.1");
        CHECK(line.method == "POST");
        CHECK(line.target == "/a/b");
        CHECK_THROWS(parseI2pHttpRequestLine("GET"));
        CHECK_THROWS(parseI2pHttpRequestLine("GET /hello"));
        CHECK_THROWS(parseI2pHttpRequestLine(""));
    }

    {
        FdStream stream = streamFrom("GET /hello HTTP/1.1\r\nHost: h");
        std::string said;
        try {
            (void)readI2pHttpRequestHead(stream);
        } catch (const std::exception& error) {
            said = error.what();
        }
        CHECK(said.find("closed after 28 bytes") != std::string::npos);
        CHECK(said.find("request head was complete") != std::string::npos);
    }

    {
        FdStream stream
            = streamFrom("GET /hello HTTP/1.1\r\nX: " + std::string(kMaxI2pHttpHeadBytes, 'y'));
        std::string said;
        try {
            (void)readI2pHttpRequestHead(stream);
        } catch (const std::exception& error) {
            said = error.what();
        }
        CHECK(said.find("i2p request head is over") != std::string::npos);
    }

    {
        CHECK(buildI2pHttpResponse(kI2pHttpOk, {{"Content-Type", "application/octet-stream"}}, 7)
            == "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
               "Content-Length: 7\r\nConnection: close\r\n\r\n");
        CHECK(buildI2pHttpResponse(kI2pHttpForbidden, {}, 0)
            == "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        CHECK(buildI2pHttpResponse(kI2pHttpNotFound, {}, 0).find("404 Not Found") == 9);
        CHECK(buildI2pHttpResponse(kI2pHttpBadRequest, {}, 0).find("400 Bad Request") == 9);
        CHECK_THROWS(buildI2pHttpResponse(418, {}, 0));
    }

    std::printf("TestI2pHttp: all checks passed\n");
    return 0;
}
