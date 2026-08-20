// Bazarish project (c) 2026
#pragma once

#include <array>
#include <cstddef>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>

namespace bazarish {

// Helpers for the minimal HTTP/1.1 exchanges Bazarish tunnels over an I2P stream
// (client blob fetch / confirm / unsend, server-core blob proxy). The wire
// convention is always: the request carries Content-Length and the server
// replies then closes (Connection: close), so reading to EOF yields the whole
// body. These centralize the request format and response parser that the client
// and the messaging server would otherwise duplicate.

// Builds the request head: "<method> <path> HTTP/1.1", a Host header, the
// caller's extra headers (verbatim, in iteration order), then
// "Content-Length: <bodySize>" and "Connection: close". Any body bytes are
// written by the caller after this head.
std::string buildI2pHttpRequest(const std::string& method, const std::string& host,
    const std::string& path, const std::map<std::string, std::string>& extraHeaders,
    std::size_t bodySize, bool keepAlive = false);

// Parses the numeric status from a status line ("HTTP/1.1 404 Not Found").
// Throws on a malformed line.
int parseI2pHttpStatus(const std::string& statusLine);

// Parses the header lines following the status line into a map with lowercased
// keys and leading-whitespace-trimmed values. The input is the head block
// (status line + headers, without the terminating blank line).
std::map<std::string, std::string> parseI2pHttpHeaders(const std::string& headBlock);

// The parsed head of an HTTP response read over an I2P stream.
struct I2pHttpHead {
    int status = 0;
    std::map<std::string, std::string> headers;  // keys lowercased
    // Body bytes already read past the CRLFCRLF head terminator.
    std::string leftover;
};

// Reads from `stream` (any type with readSome(void*, size_t) - a bazarish::i2p
// Stream) up to the CRLFCRLF head terminator and parses the status line and
// headers; any body bytes read past it are returned in `.leftover`. Throws on a
// malformed response or premature EOF. The streaming download path uses this and
// then keeps reading the body off the same stream.
template <class Stream>
I2pHttpHead readI2pHttpHead(Stream& stream)
{
    std::string raw;
    std::array<char, 65536> buffer{};
    std::size_t headerEnd = std::string::npos;
    while ((headerEnd = raw.find("\r\n\r\n")) == std::string::npos) {
        const std::size_t got = stream.readSome(buffer.data(), buffer.size());
        if (got == 0) {
            throw std::runtime_error("malformed i2p http response");
        }
        raw.append(buffer.data(), got);
    }
    const std::string headBlock = raw.substr(0, headerEnd);
    I2pHttpHead head;
    head.status = parseI2pHttpStatus(headBlock.substr(0, headBlock.find("\r\n")));
    head.headers = parseI2pHttpHeaders(headBlock);
    head.leftover = raw.substr(headerEnd + 4);
    return head;
}

// A whole HTTP response (head + body drained to EOF) for the non-streaming
// callers. The body is raw bytes (binary-safe).
struct I2pHttpResponse {
    int status = 0;
    std::map<std::string, std::string> headers;  // keys lowercased
    std::string body;
};
template <class Stream>
I2pHttpResponse readI2pHttpResponse(Stream& stream)
{
    I2pHttpHead head = readI2pHttpHead(stream);
    I2pHttpResponse response;
    response.status = head.status;
    response.headers = std::move(head.headers);
    response.body = std::move(head.leftover);
    // Content-Length decides where the body ends. Reading to EOF instead would
    // mean waiting for the other side to close - and a relay that waits for US to
    // close first (so the last write is not truncated) turns that into a stall
    // that ends only at the read timeout, on every single request.
    std::size_t expected = 0;
    bool framed = false;
    if (const auto it = response.headers.find("content-length"); it != response.headers.end()) {
        try {
            expected = static_cast<std::size_t>(std::stoull(it->second));
            framed = true;
        } catch (const std::exception&) {
            framed = false;  // unparseable length: fall back to reading to EOF
        }
    }
    std::array<char, 65536> buffer{};
    while (!framed || response.body.size() < expected) {
        const std::size_t got = stream.readSome(buffer.data(), buffer.size());
        if (got == 0) {
            break;  // EOF: all there is, framed or not
        }
        response.body.append(buffer.data(), got);
    }
    if (framed && response.body.size() > expected) {
        response.body.resize(expected);  // a keep-alive relay may hand over more
    }
    return response;
}

}  // namespace bazarish
