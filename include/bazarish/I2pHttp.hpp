// Bazarish project (c) 2026
#pragma once

#include <array>
#include <cstddef>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>

namespace bazarish {

inline constexpr std::size_t kMaxI2pHttpHeadBytes = 8 * 1024;
inline constexpr std::size_t kI2pHttpReadChunk = 64 * 1024;

inline constexpr int kI2pHttpOk = 200;
inline constexpr int kI2pHttpBadRequest = 400;
inline constexpr int kI2pHttpForbidden = 403;
inline constexpr int kI2pHttpNotFound = 404;

std::string buildI2pHttpRequest(const std::string& method, const std::string& host,
    const std::string& path, const std::map<std::string, std::string>& extraHeaders,
    std::size_t bodySize, bool keepAlive = false);

std::string buildI2pHttpResponse(int status,
    const std::map<std::string, std::string>& extraHeaders, std::size_t bodySize);

int parseI2pHttpStatus(const std::string& statusLine);

struct I2pHttpRequestLine {
    std::string method;
    std::string target;
};

I2pHttpRequestLine parseI2pHttpRequestLine(const std::string& requestLine);

std::map<std::string, std::string> parseI2pHttpHeaders(const std::string& headBlock);

template <class Stream>
std::string readI2pHttpHeadBlock(Stream& stream, std::string& leftover, const std::string& kind)
{
    const std::string terminator = "\r\n\r\n";
    std::string raw;
    std::array<char, kI2pHttpReadChunk> buffer{};
    std::size_t headerEnd = std::string::npos;
    while ((headerEnd = raw.find(terminator)) == std::string::npos) {
        if (raw.size() > kMaxI2pHttpHeadBytes) {
            throw std::runtime_error("i2p " + kind + " head is over "
                + std::to_string(kMaxI2pHttpHeadBytes) + " bytes");
        }
        const std::size_t got = stream.readSome(buffer.data(), buffer.size());
        if (got == 0) {
            throw std::runtime_error("i2p stream closed after " + std::to_string(raw.size())
                + " bytes, before the " + kind + " head was complete");
        }
        raw.append(buffer.data(), got);
    }
    leftover = raw.substr(headerEnd + terminator.size());
    return raw.substr(0, headerEnd);
}

struct I2pHttpHead {
    int status = 0;
    std::map<std::string, std::string> headers;
    std::string leftover;
};

template <class Stream>
I2pHttpHead readI2pHttpHead(Stream& stream)
{
    I2pHttpHead head;
    const std::string headBlock = readI2pHttpHeadBlock(stream, head.leftover, "response");
    head.status = parseI2pHttpStatus(headBlock.substr(0, headBlock.find("\r\n")));
    head.headers = parseI2pHttpHeaders(headBlock);
    return head;
}

struct I2pHttpRequestHead {
    std::string method;
    std::string target;
    std::map<std::string, std::string> headers;
    std::string leftover;
};

template <class Stream>
I2pHttpRequestHead readI2pHttpRequestHead(Stream& stream)
{
    I2pHttpRequestHead head;
    const std::string headBlock = readI2pHttpHeadBlock(stream, head.leftover, "request");
    const I2pHttpRequestLine line
        = parseI2pHttpRequestLine(headBlock.substr(0, headBlock.find("\r\n")));
    head.method = line.method;
    head.target = line.target;
    head.headers = parseI2pHttpHeaders(headBlock);
    return head;
}

struct I2pHttpResponse {
    int status = 0;
    std::map<std::string, std::string> headers;
    std::string body;
};

template <class Stream>
I2pHttpResponse readI2pHttpResponse(Stream& stream, const std::size_t maxBodyBytes)
{
    const auto refuseOversized = [maxBodyBytes](const std::size_t got) {
        if (got > maxBodyBytes) {
            throw std::runtime_error("i2p response body is over " + std::to_string(maxBodyBytes)
                + " bytes");
        }
    };
    I2pHttpHead head = readI2pHttpHead(stream);
    I2pHttpResponse response;
    response.status = head.status;
    response.headers = std::move(head.headers);
    response.body = std::move(head.leftover);
    refuseOversized(response.body.size());
    std::size_t expected = 0;
    bool framed = false;
    if (const auto it = response.headers.find("content-length"); it != response.headers.end()) {
        try {
            expected = static_cast<std::size_t>(std::stoull(it->second));
            framed = true;
        } catch (const std::exception&) {
            framed = false;
        }
    }
    if (framed) {
        refuseOversized(expected);
    }
    std::array<char, 65536> buffer{};
    while (!framed || response.body.size() < expected) {
        const std::size_t got = stream.readSome(buffer.data(), buffer.size());
        if (got == 0) {
            break;
        }
        response.body.append(buffer.data(), got);
        refuseOversized(response.body.size());
    }
    if (framed && response.body.size() > expected) {
        response.body.resize(expected);
    }
    return response;
}

}  // namespace bazarish
