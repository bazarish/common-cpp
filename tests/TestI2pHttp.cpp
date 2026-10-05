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

// A minimal stand-in for bazarish::i2p::Stream: anything with readSome(void*,
// size_t) drives the templated readers. Backed by a socketpair fd so the parser
// reads real bytes without needing any I2P transport.
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

// Pushes `data` into one end of a socketpair, closes that end (so the reader sees
// EOF), and wraps the other end in an FdStream for the parser to read.
FdStream streamFrom(const std::string& data)
{
    int fds[2] = {-1, -1};
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    CHECK(::write(fds[1], data.data(), data.size()) == static_cast<ssize_t>(data.size()));
    CHECK(::close(fds[1]) == 0);  // EOF for the reader
    return FdStream(fds[0]);
}

// Above anything the other cases present, so the bound is only ever the subject
// of the cases that are about it.
constexpr std::size_t kSomeBodyBound = 64 * 1024;

}  // namespace

int main()
{
    // buildI2pHttpRequest: request line, Host, extra headers, Content-Length and
    // Connection: close.
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

    // parseI2pHttpStatus: the numeric code; a line with no space is malformed.
    {
        CHECK(parseI2pHttpStatus("HTTP/1.1 200 OK") == 200);
        CHECK(parseI2pHttpStatus("HTTP/1.1 404 Not Found") == 404);
        CHECK_THROWS(parseI2pHttpStatus("garbage-no-space"));
    }

    // parseI2pHttpHeaders: lowercased keys, whitespace-trimmed values, the status
    // line and any colon-less line skipped.
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

    // readI2pHttpResponse over a real stream: status + headers + body to EOF.
    {
        FdStream stream
            = streamFrom("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
        const I2pHttpResponse response = readI2pHttpResponse(stream, kSomeBodyBound);
        CHECK(response.status == 200);
        CHECK(response.headers.at("content-length") == "5");
        CHECK(response.body == "hello");
    }

    // readI2pHttpHead: leftover carries the body bytes buffered past the head.
    {
        FdStream stream
            = streamFrom("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot-found");
        const I2pHttpHead head = readI2pHttpHead(stream);
        CHECK(head.status == 404);
        CHECK(head.headers.at("content-length") == "9");
        CHECK(head.leftover == "not-found");
    }

    // A route that dies mid-response says so, and says how far it got: the reader
    // of this message otherwise goes looking for a peer speaking bad HTTP when
    // what happened is that the stream went away.
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

    // A head with no body (an empty 200).
    {
        FdStream stream = streamFrom("HTTP/1.1 200 OK\r\n\r\n");
        const I2pHttpResponse response = readI2pHttpResponse(stream, kSomeBodyBound);
        CHECK(response.status == 200);
        CHECK(response.body.empty());
    }

    // A body over the caller's bound is refused, by what it says it weighs...
    {
        FdStream stream = streamFrom("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n");
        CHECK_THROWS(readI2pHttpResponse(stream, 10));
    }

    // ...and by what it actually sends, when it says nothing.
    {
        FdStream stream = streamFrom("HTTP/1.1 200 OK\r\n\r\n0123456789abc");
        CHECK_THROWS(readI2pHttpResponse(stream, 10));
    }

    // A head over the bound is refused, and says so rather than as a dead route.
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

    std::printf("TestI2pHttp: all checks passed\n");
    return 0;
}
