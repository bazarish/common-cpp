// Bazarish project (c) 2026
#pragma once

#include <array>
#include <cstddef>
#include <map>
#include <stdexcept>
#include <string>

namespace bazarish {

// Helpers for the minimal HTTP/1.1 exchanges Bazarish tunnels over a SAM stream
// (client blob fetch / confirm / unsend, server-core blob proxy). The wire
// convention is always: the request carries Content-Length and the server
// replies then closes (Connection: close). No half-close is used because SAM
// treats SHUT_WR as a full stream teardown, so reading to EOF yields the whole
// body. These centralize the request format and response parser that the client
// and the messaging server would otherwise duplicate.

// Builds the request head: "<method> <path> HTTP/1.1", a Host header, the
// caller's extra headers (verbatim, in iteration order), then
// "Content-Length: <bodySize>" and "Connection: close". Any body bytes are
// written by the caller after this head.
std::string buildSamHttpRequest(const std::string& method, const std::string& host,
    const std::string& path, const std::map<std::string, std::string>& extraHeaders,
    std::size_t bodySize);

// Parses the numeric status from a status line ("HTTP/1.1 404 Not Found").
// Throws on a malformed line.
int parseSamHttpStatus(const std::string& statusLine);

// Parses the header lines following the status line into a map with lowercased
// keys and leading-whitespace-trimmed values. The input is the head block
// (status line + headers, without the terminating blank line).
std::map<std::string, std::string> parseSamHttpHeaders(const std::string& headBlock);

// The parsed head of an HTTP response read over a SAM stream.
struct SamHttpHead {
    int status = 0;
    std::map<std::string, std::string> headers;  // keys lowercased
    // Body bytes already read past the CRLFCRLF head terminator.
    std::string leftover;
};

// Reads from `stream` (any type with readSome(void*, size_t) - a SAM stream or a
// bazarish::i2p::Stream) up to the CRLFCRLF head terminator and parses the status
// line and headers; any body bytes read past it are returned in `.leftover`.
// Throws on a malformed response or premature EOF. The streaming download path
// uses this and then keeps reading the body off the same stream.
template <class Stream>
SamHttpHead readSamHttpHead(Stream& stream)
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
    SamHttpHead head;
    head.status = parseSamHttpStatus(headBlock.substr(0, headBlock.find("\r\n")));
    head.headers = parseSamHttpHeaders(headBlock);
    head.leftover = raw.substr(headerEnd + 4);
    return head;
}

// A whole HTTP response (head + body drained to EOF) for the non-streaming
// callers. The body is raw bytes (binary-safe).
struct SamHttpResponse {
    int status = 0;
    std::map<std::string, std::string> headers;  // keys lowercased
    std::string body;
};
template <class Stream>
SamHttpResponse readSamHttpResponse(Stream& stream)
{
    SamHttpHead head = readSamHttpHead(stream);
    SamHttpResponse response;
    response.status = head.status;
    response.headers = std::move(head.headers);
    response.body = std::move(head.leftover);
    std::array<char, 65536> buffer{};
    for (;;) {
        const std::size_t got = stream.readSome(buffer.data(), buffer.size());
        if (got == 0) {
            break;
        }
        response.body.append(buffer.data(), got);
    }
    return response;
}

}  // namespace bazarish
