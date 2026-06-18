// Bazarish project (c) 2026
#include "bazarish/SamHttp.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>

namespace bazarish {

std::string buildSamHttpRequest(const std::string& method, const std::string& host,
    const std::string& path, const std::map<std::string, std::string>& extraHeaders,
    const std::size_t bodySize)
{
    std::string request = method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n";
    for (const auto& [key, value] : extraHeaders) {
        request += key + ": " + value + "\r\n";
    }
    request += "Content-Length: " + std::to_string(bodySize) + "\r\nConnection: close\r\n\r\n";
    return request;
}

int parseSamHttpStatus(const std::string& statusLine)
{
    const std::size_t space = statusLine.find(' ');
    if (space == std::string::npos) {
        throw std::runtime_error("malformed i2p http status line");
    }
    return std::stoi(statusLine.substr(space + 1, 3));
}

std::map<std::string, std::string> parseSamHttpHeaders(const std::string& headBlock)
{
    std::map<std::string, std::string> headers;
    const std::size_t firstLineEnd = headBlock.find("\r\n");
    std::size_t lineStart
        = (firstLineEnd == std::string::npos) ? headBlock.size() : firstLineEnd + 2;
    while (lineStart < headBlock.size()) {
        const std::size_t lineEnd = headBlock.find("\r\n", lineStart);
        const std::size_t stop = (lineEnd == std::string::npos) ? headBlock.size() : lineEnd;
        const std::string line = headBlock.substr(lineStart, stop - lineStart);
        lineStart = (lineEnd == std::string::npos) ? headBlock.size() : lineEnd + 2;
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        std::string key = line.substr(0, colon);
        std::transform(key.begin(), key.end(), key.begin(),
            [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::size_t valueStart = colon + 1;
        while (valueStart < line.size() && (line[valueStart] == ' ' || line[valueStart] == '\t')) {
            ++valueStart;
        }
        headers[key] = line.substr(valueStart);
    }
    return headers;
}

SamHttpHead readSamHttpHead(SamStream& stream)
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

SamHttpResponse readSamHttpResponse(SamStream& stream)
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
