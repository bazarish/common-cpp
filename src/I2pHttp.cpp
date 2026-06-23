// Bazarish project (c) 2026
#include "bazarish/I2pHttp.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>

namespace bazarish {

std::string buildI2pHttpRequest(const std::string& method, const std::string& host,
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

int parseI2pHttpStatus(const std::string& statusLine)
{
    const std::size_t space = statusLine.find(' ');
    if (space == std::string::npos) {
        throw std::runtime_error("malformed i2p http status line");
    }
    return std::stoi(statusLine.substr(space + 1, 3));
}

std::map<std::string, std::string> parseI2pHttpHeaders(const std::string& headBlock)
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

}  // namespace bazarish
