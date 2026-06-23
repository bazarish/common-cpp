// Bazarish project (c) 2026
#include "bazarish/SamHttp.hpp"

#include "bazarish/Sam.hpp"  // SamStream, as a concrete stream to exercise the templated readers

#include "TestUtil.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <string>
#include <sys/types.h>

using namespace bazarish;

namespace {

// Pushes `data` into one end of a socketpair, closes that end (so the reader
// sees EOF), and wraps the other end in a SamStream - a real stream for the
// parser to read without needing a SAM bridge.
SamStream streamFrom(const std::string& data)
{
    int fds[2] = {-1, -1};
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    CHECK(::write(fds[1], data.data(), data.size()) == static_cast<ssize_t>(data.size()));
    CHECK(::close(fds[1]) == 0);  // EOF for the reader
    return SamStream(fds[0]);
}

}  // namespace

int main()
{
    // buildSamHttpRequest: request line, Host, extra headers, Content-Length and
    // Connection: close.
    {
        const std::string get
            = buildSamHttpRequest("GET", "h.b32.i2p", "/b/x", {{"Range", "bytes=10-"}}, 0);
        CHECK(get
            == "GET /b/x HTTP/1.1\r\nHost: h.b32.i2p\r\n"
               "Range: bytes=10-\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        const std::string post
            = buildSamHttpRequest("POST", "h.b32.i2p", "/b/x/confirm", {}, 42);
        CHECK(post
            == "POST /b/x/confirm HTTP/1.1\r\nHost: h.b32.i2p\r\n"
               "Content-Length: 42\r\nConnection: close\r\n\r\n");
    }

    // parseSamHttpStatus: the numeric code; a line with no space is malformed.
    {
        CHECK(parseSamHttpStatus("HTTP/1.1 200 OK") == 200);
        CHECK(parseSamHttpStatus("HTTP/1.1 404 Not Found") == 404);
        CHECK_THROWS(parseSamHttpStatus("garbage-no-space"));
    }

    // parseSamHttpHeaders: lowercased keys, whitespace-trimmed values, the status
    // line and any colon-less line skipped.
    {
        const std::map<std::string, std::string> headers = parseSamHttpHeaders(
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

    // readSamHttpResponse over a real stream: status + headers + body to EOF.
    {
        SamStream stream
            = streamFrom("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
        const SamHttpResponse response = readSamHttpResponse(stream);
        CHECK(response.status == 200);
        CHECK(response.headers.at("content-length") == "5");
        CHECK(response.body == "hello");
    }

    // readSamHttpHead: leftover carries the body bytes buffered past the head.
    {
        SamStream stream
            = streamFrom("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot-found");
        const SamHttpHead head = readSamHttpHead(stream);
        CHECK(head.status == 404);
        CHECK(head.headers.at("content-length") == "9");
        CHECK(head.leftover == "not-found");
    }

    // A head with no body (an empty 200).
    {
        SamStream stream = streamFrom("HTTP/1.1 200 OK\r\n\r\n");
        const SamHttpResponse response = readSamHttpResponse(stream);
        CHECK(response.status == 200);
        CHECK(response.body.empty());
    }

    std::printf("TestSamHttp: all checks passed\n");
    return 0;
}
