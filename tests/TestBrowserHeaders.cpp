// Bazarish project (c) 2026
#include "bazarish/WebSocketClient.hpp"

#include "TestUtil.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace bazarish;
using namespace bazarish::http;

namespace {

constexpr char kLoopback[] = "127.0.0.1";
constexpr char kHost[] = "localhost";
constexpr char kPath[] = "/page";
constexpr char kCookie[] = "sid=abc";
constexpr std::string_view kHeadEnd = "\r\n\r\n";
constexpr std::string_view kLineEnd = "\r\n";
constexpr std::string_view kSeparator = ": ";
constexpr std::size_t kBufferBytes = 4096;
// Base64 of the 16 random bytes RFC 6455 4.1 asks for.
constexpr std::size_t kKeyChars = 24;
constexpr char kChromeVersion[] = "Chrome/157.0.0.0 ";

// Chrome 157.0.8103.78 as captured 2026-11-12 over https, with a cookie set.
const std::vector<std::string> kUpgradeOrder{"Host", "Connection", "Pragma", "Cache-Control",
    "User-Agent", "Upgrade", "Origin", "Sec-WebSocket-Version", "Accept-Encoding",
    "Accept-Language", "Cookie", "Sec-WebSocket-Key", "Sec-WebSocket-Extensions"};
const std::vector<std::string> kDocumentOrder{"Host", "Connection", "sec-ch-ua",
    "sec-ch-ua-mobile", "sec-ch-ua-platform", "Upgrade-Insecure-Requests", "User-Agent", "Accept",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding",
    "Accept-Language", "Cookie"};
const std::vector<std::string> kImageOrder{"Host", "Connection", "sec-ch-ua-platform",
    "User-Agent", "sec-ch-ua", "sec-ch-ua-mobile", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode",
    "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language", "Cookie"};

std::string capture(const std::function<void(int)>& ask)
{
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = ::inet_addr(kLoopback);
    CHECK(::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0);
    CHECK(::listen(listener, 1) == 0);
    socklen_t length = sizeof address;
    CHECK(::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0);
    const int port = ntohs(address.sin_port);

    std::string head;
    std::thread taker([&head, listener]() {
        const int in = ::accept(listener, nullptr, nullptr);
        CHECK(in >= 0);
        std::array<char, kBufferBytes> buffer{};
        while (head.find(kHeadEnd) == std::string::npos) {
            const ssize_t got = ::recv(in, buffer.data(), buffer.size(), 0);
            if (got <= 0) {
                break;
            }
            head.append(buffer.data(), static_cast<std::size_t>(got));
        }
        ::close(in);
    });
    ask(port);
    taker.join();
    ::close(listener);
    return head;
}

std::vector<std::pair<std::string, std::string>> fieldsOf(const std::string& head)
{
    std::vector<std::pair<std::string, std::string>> fields;
    std::size_t at = head.find(kLineEnd) + kLineEnd.size();
    for (;;) {
        const std::size_t end = head.find(kLineEnd, at);
        if (end == std::string::npos || end == at) {
            break;
        }
        const std::string line = head.substr(at, end - at);
        const std::size_t colon = line.find(kSeparator);
        CHECK(colon != std::string::npos);
        fields.emplace_back(line.substr(0, colon), line.substr(colon + kSeparator.size()));
        at = end + kLineEnd.size();
    }
    return fields;
}

std::vector<std::string> namesOf(const std::vector<std::pair<std::string, std::string>>& fields)
{
    std::vector<std::string> names;
    for (const auto& [name, value] : fields) {
        names.push_back(name);
    }
    return names;
}

std::string valueOf(
    const std::vector<std::pair<std::string, std::string>>& fields, const std::string& name)
{
    for (const auto& [field, value] : fields) {
        if (field == name) {
            return value;
        }
    }
    return {};
}

SocketDial dialTo(const int port)
{
    SocketDial dial;
    dial.host = kHost;
    dial.port = port;
    dial.path = kPath;
    dial.tls = false;
    dial.connectTimeout = std::chrono::seconds(5);
    return dial;
}

}  // namespace

int main()
{
    int upgradePort = 0;
    const std::string upgrade = capture([&upgradePort](const int port) {
        upgradePort = port;
        SocketDial dial = dialTo(port);
        dial.headers = {{"Cookie", kCookie}};
        CHECK(openSocket(dial, nullptr, nullptr).socket == nullptr);
    });
    const auto upgradeFields = fieldsOf(upgrade);
    CHECK(upgrade.rfind(std::string("GET ") + kPath + " HTTP/1.1\r\n", 0) == 0);
    CHECK(namesOf(upgradeFields) == kUpgradeOrder);
    CHECK(valueOf(upgradeFields, "Host") == std::string(kHost) + ":" + std::to_string(upgradePort));
    CHECK(valueOf(upgradeFields, "Origin")
        == std::string("http://") + kHost + ":" + std::to_string(upgradePort));
    CHECK(valueOf(upgradeFields, "Connection") == "Upgrade");
    CHECK(valueOf(upgradeFields, "Upgrade") == "websocket");
    CHECK(valueOf(upgradeFields, "Sec-WebSocket-Version") == "13");
    CHECK(valueOf(upgradeFields, "Sec-WebSocket-Key").size() == kKeyChars);
    CHECK(valueOf(upgradeFields, "Cookie") == kCookie);
    CHECK(valueOf(upgradeFields, "User-Agent").find(kChromeVersion) != std::string::npos);

    const std::map<std::string, std::string> cookie{{"Cookie", kCookie}};
    std::size_t expectedBytes = 0;
    const std::string document = capture([&](const int port) {
        expectedBytes = fetchBytes(dialTo(port), kPath, Fetch::eDocument, cookie);
        KeptConnection connection(dialTo(port));
        CHECK(connection.connected());
        CHECK(!connection.get(kPath, Fetch::eDocument, cookie).reached);
    });
    const auto documentFields = fieldsOf(document);
    CHECK(namesOf(documentFields) == kDocumentOrder);
    CHECK(document.size() == expectedBytes);
    CHECK(valueOf(documentFields, "Sec-Fetch-Mode") == "navigate");

    int imagePort = 0;
    const std::string image = capture([&](const int port) {
        imagePort = port;
        expectedBytes = fetchBytes(dialTo(port), kPath, Fetch::eImage, cookie);
        KeptConnection connection(dialTo(port));
        CHECK(connection.connected());
        CHECK(!connection.get(kPath, Fetch::eImage, cookie).reached);
    });
    const auto imageFields = fieldsOf(image);
    CHECK(namesOf(imageFields) == kImageOrder);
    CHECK(image.size() == expectedBytes);
    CHECK(valueOf(imageFields, "Referer")
        == std::string("http://") + kHost + ":" + std::to_string(imagePort) + kPath);
    CHECK(valueOf(imageFields, "Sec-Fetch-Dest") == "image");

    std::puts("TestBrowserHeaders ok");
    return 0;
}
