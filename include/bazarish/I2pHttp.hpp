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

std::string buildI2pHttpRequest(const std::string& method, const std::string& host,
    const std::string& path, const std::map<std::string, std::string>& extraHeaders,
    std::size_t bodySize, bool keepAlive = false);

int parseI2pHttpStatus(const std::string& statusLine);

std::map<std::string, std::string> parseI2pHttpHeaders(const std::string& headBlock);

struct I2pHttpHead {
    int status = 0;
    std::map<std::string, std::string> headers;
    std::string leftover;
};

template <class Stream>
I2pHttpHead readI2pHttpHead(Stream& stream)
{
    std::string raw;
    std::array<char, 65536> buffer{};
    std::size_t headerEnd = std::string::npos;
    while ((headerEnd = raw.find("\r\n\r\n")) == std::string::npos) {
        const std::size_t got = stream.readSome(buffer.data(), buffer.size());
        if (got == 0) {
            throw std::runtime_error("i2p stream closed after " + std::to_string(raw.size())
                + " bytes, before the response head was complete");
        }
        raw.append(buffer.data(), got);
        if (raw.size() > kMaxI2pHttpHeadBytes) {
            throw std::runtime_error(
                "i2p response head is over " + std::to_string(kMaxI2pHttpHeadBytes) + " bytes");
        }
    }
    const std::string headBlock = raw.substr(0, headerEnd);
    I2pHttpHead head;
    head.status = parseI2pHttpStatus(headBlock.substr(0, headBlock.find("\r\n")));
    head.headers = parseI2pHttpHeaders(headBlock);
    head.leftover = raw.substr(headerEnd + 4);
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
