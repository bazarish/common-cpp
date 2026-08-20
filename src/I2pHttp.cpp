// Bazarish project (c) 2026
#include "bazarish/I2pHttp.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>

namespace bazarish {

std::string buildI2pHttpRequest(const std::string& method, const std::string& host,
    const std::string& path, const std::map<std::string, std::string>& extraHeaders,
    const std::size_t bodySize, const bool keepAlive)
{
    std::string request = method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n";
    for (const auto& [key, value] : extraHeaders) {
        request += key + ": " + value + "\r\n";
    }
    request += "Content-Length: " + std::to_string(bodySize) + "\r\nConnection: "
        + (keepAlive ? "keep-alive" : "close") + "\r\n\r\n";
    return request;
}

namespace {

// How much of an unparseable first line is quoted back in the error. Enough to
// tell an HTTP status line from a request line or a relay's plain-text refusal,
// short enough that no body can ride along in a log.
constexpr std::size_t kQuotedLineLimit = 64;
// Status codes are three digits.
constexpr std::size_t kStatusCodeDigits = 3;

std::string quoteForError(const std::string& line)
{
    std::string quoted;
    for (const char c : line.substr(0, kQuotedLineLimit)) {
        quoted += (std::isprint(static_cast<unsigned char>(c)) != 0) ? c : '.';
    }
    return "\"" + quoted + "\"";
}

}  // namespace

int parseI2pHttpStatus(const std::string& statusLine)
{
    // Quote the line itself: "not a status line" is the same message whether the
    // other side sent a request, a relay's plain refusal, or another response's
    // body, and those have very different causes.
    const std::size_t space = statusLine.find(' ');
    if (space == std::string::npos) {
        throw std::runtime_error("malformed i2p http status line: " + quoteForError(statusLine));
    }
    try {
        return std::stoi(statusLine.substr(space + 1, kStatusCodeDigits));
    } catch (const std::exception&) {
        throw std::runtime_error("i2p http reply is not a response: " + quoteForError(statusLine));
    }
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
