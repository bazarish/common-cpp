// Bazarish project (c) 2026
#include "bazarish/WebSocketClient.hpp"

#include "TestUtil.hpp"
#include "WebCredential.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <csignal>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::http;

namespace {

// Chrome 157.0.8103.78 on Linux, captured 2026-11-12; JA3N is JA3 with extensions sorted.
constexpr char kChromePageJa4[] = "t13d1517h2_8daaf6152771_cb7bf5808d99";
constexpr char kChromeWebSocketJa4[] = "t13d1516h1_8daaf6152771_5b37b36a67c0";
constexpr char kChromePageJa3n[] = "bd4930bd9b000ee684830e44bab76fdf";
constexpr char kChromeWebSocketJa3n[] = "11a7f5f23ec2a0977c070e6bf5b708c8";
// The same Chrome's WebSocket opened after a page of that host: it resumes the page's session.
constexpr char kChromeResumedWebSocketJa4[] = "t13d1517h1_8daaf6152771_c4a234726a38";

constexpr char kHost[] = "localhost";
constexpr char kLoopback[] = "127.0.0.1";
constexpr char kAnswer[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
constexpr char kRequest[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
constexpr std::string_view kHeadEnd = "\r\n\r\n";
constexpr std::uint8_t kClientHello = 1;
constexpr std::uint16_t kTls12 = 0x0303;
constexpr std::uint16_t kTls13 = 0x0304;
// RFC 6066, 7301, 8446: the extensions JA4 names or reads.
constexpr std::uint16_t kServerName = 0x0000;
constexpr std::uint16_t kSupportedGroups = 0x000a;
constexpr std::uint16_t kPointFormats = 0x000b;
constexpr std::uint16_t kSignatureAlgorithms = 0x000d;
constexpr std::uint16_t kAlpn = 0x0010;
constexpr std::uint16_t kPreSharedKey = 0x0029;
constexpr std::uint16_t kSupportedVersions = 0x002b;
// RFC 8701: every GREASE value is 0x?A?A with both bytes equal.
constexpr std::uint16_t kGreaseMask = 0x0f0f;
constexpr std::uint16_t kGreaseValue = 0x0a0a;
constexpr std::uint16_t kLowByte = 0x00ff;
constexpr std::size_t kJa4HashChars = 12;
constexpr std::size_t kHandshakeHeaderBytes = 4;
// A list behind a one-byte or a two-byte length, RFC 8446 4.2.
constexpr std::size_t kShortListOffset = 1;
constexpr std::size_t kListOffset = sizeof(std::uint16_t);
constexpr std::size_t kRandomBytes = 32;
constexpr int kBitsPerByte = 8;
constexpr std::size_t kBufferBytes = 16384;
constexpr int kFreshConnections = 4;
constexpr int kMixedThreads = 4;
constexpr int kMixedRounds = 10;
constexpr int kSmallCount = 100;

template <auto Free>
struct Freer {
    template <class Handle>
    void operator()(Handle* const handle) const
    {
        Free(handle);
    }
};
using SslPtr = std::unique_ptr<SSL, Freer<&SSL_free>>;
using SslContextPtr = std::unique_ptr<SSL_CTX, Freer<&SSL_CTX_free>>;

bool grease(const std::uint16_t value)
{
    return (value & kGreaseMask) == kGreaseValue && (value >> kBitsPerByte) == (value & kLowByte);
}

class Reader {
public:
    explicit Reader(const std::vector<std::uint8_t>& bytes)
        : bytes_(bytes)
    {
    }
    std::uint8_t u8() { return bytes_.at(at_++); }
    std::uint16_t u16()
    {
        const std::uint16_t high = u8();
        return static_cast<std::uint16_t>((high << kBitsPerByte) | u8());
    }
    std::vector<std::uint8_t> take(const std::size_t count)
    {
        CHECK(at_ + count <= bytes_.size());
        const std::vector<std::uint8_t> out(bytes_.begin() + static_cast<long>(at_),
            bytes_.begin() + static_cast<long>(at_ + count));
        at_ += count;
        return out;
    }
    void skip(const std::size_t count) { static_cast<void>(take(count)); }
    bool done() const { return at_ >= bytes_.size(); }

private:
    const std::vector<std::uint8_t>& bytes_;
    std::size_t at_ = 0;
};

std::vector<std::uint16_t> u16List(const std::vector<std::uint8_t>& bytes, const std::size_t from)
{
    std::vector<std::uint16_t> out;
    for (std::size_t at = from; at + 1 < bytes.size(); at += 2) {
        out.push_back(static_cast<std::uint16_t>((bytes[at] << kBitsPerByte) | bytes[at + 1]));
    }
    return out;
}

struct Hello {
    std::vector<std::uint16_t> ciphers;
    std::vector<std::pair<std::uint16_t, std::vector<std::uint8_t>>> extensions;

    const std::vector<std::uint8_t>* find(const std::uint16_t type) const
    {
        for (const auto& [kind, body] : extensions) {
            if (kind == type) {
                return &body;
            }
        }
        return nullptr;
    }
    std::vector<std::uint16_t> order() const
    {
        std::vector<std::uint16_t> types;
        for (const auto& [kind, body] : extensions) {
            types.push_back(kind);
        }
        return types;
    }
};

Hello parse(const std::vector<std::uint8_t>& message)
{
    Reader reader(message);
    CHECK(reader.u8() == kClientHello);
    reader.skip(kHandshakeHeaderBytes - 1);
    reader.skip(sizeof(std::uint16_t) + kRandomBytes);
    reader.skip(reader.u8());
    Hello hello;
    const std::uint16_t cipherBytes = reader.u16();
    hello.ciphers = u16List(reader.take(cipherBytes), 0);
    reader.skip(reader.u8());
    const std::uint16_t extensionBytes = reader.u16();
    const std::vector<std::uint8_t> extensions = reader.take(extensionBytes);
    Reader inner(extensions);
    while (!inner.done()) {
        const std::uint16_t type = inner.u16();
        const std::uint16_t length = inner.u16();
        hello.extensions.emplace_back(type, inner.take(length));
    }
    return hello;
}

std::string digestHex(const EVP_MD* const md, const std::string& text)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned length = 0;
    CHECK(EVP_Digest(text.data(), text.size(), digest.data(), &length, md, nullptr) == 1);
    std::string hex;
    for (unsigned at = 0; at < length; ++at) {
        std::array<char, 3> pair{};
        std::snprintf(pair.data(), pair.size(), "%02x", digest[at]);
        hex += pair.data();
    }
    return hex;
}

std::string hex4(const std::uint16_t value)
{
    std::array<char, 5> text{};
    std::snprintf(text.data(), text.size(), "%04x", value);
    return text.data();
}

template <class Values, class Format>
std::string joined(const Values& values, const char* const separator, Format format)
{
    std::string out;
    for (const auto& value : values) {
        out += (out.empty() ? "" : separator) + format(value);
    }
    return out;
}

std::vector<std::uint16_t> withoutGrease(const std::vector<std::uint16_t>& values)
{
    std::vector<std::uint16_t> out;
    std::copy_if(values.begin(), values.end(), std::back_inserter(out),
        [](const std::uint16_t value) { return !grease(value); });
    return out;
}

std::string ja4(const Hello& hello)
{
    const std::vector<std::uint16_t> ciphers = withoutGrease(hello.ciphers);
    const std::vector<std::uint16_t> extensions = withoutGrease(hello.order());
    std::uint16_t version = kTls12;
    if (const auto* const versions = hello.find(kSupportedVersions)) {
        for (const std::uint16_t offered : withoutGrease(u16List(*versions, kShortListOffset))) {
            version = std::max(version, offered);
        }
    }
    std::string alpn = "00";
    if (const auto* const protocols = hello.find(kAlpn)) {
        const std::size_t length = protocols->at(kListOffset);
        const auto name = protocols->begin() + kListOffset + kShortListOffset;
        const std::string first(name, name + static_cast<long>(length));
        alpn = std::string() + first.front() + first.back();
    }
    std::array<char, kSmallCount> head{};
    std::snprintf(head.data(), head.size(), "t%s%c%02zu%02zu%s",
        version == kTls13 ? "13" : "12", hello.find(kServerName) != nullptr ? 'd' : 'i',
        ciphers.size(), extensions.size(), alpn.c_str());

    std::vector<std::uint16_t> sortedCiphers = ciphers;
    std::sort(sortedCiphers.begin(), sortedCiphers.end());
    std::vector<std::uint16_t> counted;
    std::copy_if(extensions.begin(), extensions.end(), std::back_inserter(counted),
        [](const std::uint16_t type) { return type != kServerName && type != kAlpn; });
    std::sort(counted.begin(), counted.end());
    std::string extensionText = joined(counted, ",", hex4);
    if (const auto* const sigalgs = hello.find(kSignatureAlgorithms)) {
        extensionText += "_" + joined(withoutGrease(u16List(*sigalgs, kListOffset)), ",", hex4);
    }
    return std::string(head.data()) + "_"
        + digestHex(EVP_sha256(), joined(sortedCiphers, ",", hex4)).substr(0, kJa4HashChars) + "_"
        + digestHex(EVP_sha256(), extensionText).substr(0, kJa4HashChars);
}

std::string ja3n(const Hello& hello)
{
    const auto decimal = [](const auto value) { return std::to_string(value); };
    std::vector<std::uint16_t> extensions = withoutGrease(hello.order());
    std::sort(extensions.begin(), extensions.end());
    std::vector<std::uint16_t> groups;
    if (const auto* const offered = hello.find(kSupportedGroups)) {
        groups = withoutGrease(u16List(*offered, kListOffset));
    }
    std::vector<int> formats;
    if (const auto* const offered = hello.find(kPointFormats)) {
        formats.assign(offered->begin() + kShortListOffset, offered->end());
    }
    const std::string text = std::to_string(kTls12) + ","
        + joined(withoutGrease(hello.ciphers), "-", decimal) + ","
        + joined(extensions, "-", decimal) + "," + joined(groups, "-", decimal) + ","
        + joined(formats, "-", decimal);
    return digestHex(EVP_md5(), text);
}

int listening(int& port)
{
    const int handle = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(handle >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = ::inet_addr(kLoopback);
    CHECK(::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0);
    CHECK(::listen(handle, kSmallCount) == 0);
    socklen_t length = sizeof address;
    CHECK(::getsockname(handle, reinterpret_cast<sockaddr*>(&address), &length) == 0);
    port = ntohs(address.sin_port);
    return handle;
}

// An OpenSSL server that keeps every ClientHello it is sent and answers each request with "ok".
class HelloServer {
public:
    HelloServer(const tls::Credential& credential, std::string chosen)
        : chosen_(std::move(chosen))
        , context_(SSL_CTX_new(TLS_server_method()))
    {
        CHECK(context_ != nullptr);
        CHECK(SSL_CTX_use_certificate_chain_file(
                  context_.get(), credential.certificate.string().c_str())
            == 1);
        CHECK(SSL_CTX_use_PrivateKey_file(
                  context_.get(), credential.key.string().c_str(), SSL_FILETYPE_PEM)
            == 1);
        SSL_CTX_set_msg_callback(context_.get(), heard);
        CHECK(SSL_CTX_set_app_data(context_.get(), this) == 1);
        SSL_CTX_set_alpn_select_cb(context_.get(), choose, this);
        listen_ = listening(port_);
        acceptor_ = std::thread([this]() { acceptAll(); });
    }

    ~HelloServer()
    {
        running_.store(false);
        ::shutdown(listen_, SHUT_RDWR);
        ::close(listen_);
        acceptor_.join();
        for (std::thread& worker : workers_) {
            worker.join();
        }
    }

    int port() const { return port_; }

    std::vector<Hello> hellos() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Hello> parsed;
        for (const auto& message : hellos_) {
            parsed.push_back(parse(message));
        }
        return parsed;
    }

private:
    static void heard(const int written, int, const int type, const void* const data,
        const std::size_t length, SSL* const ssl, void*)
    {
        const auto* const bytes = static_cast<const std::uint8_t*>(data);
        if (written != 0 || type != SSL3_RT_HANDSHAKE || length == 0 || bytes[0] != kClientHello) {
            return;
        }
        auto* const self = static_cast<HelloServer*>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
        const std::lock_guard<std::mutex> lock(self->mutex_);
        self->hellos_.emplace_back(bytes, bytes + length);
    }

    static int choose(SSL*, const unsigned char** out, unsigned char* outLength,
        const unsigned char* in, const unsigned inLength, void* const arg)
    {
        const auto* const self = static_cast<const HelloServer*>(arg);
        for (unsigned at = 0; at < inLength; at += 1U + in[at]) {
            const std::string offered(in + at + 1, in + at + 1 + in[at]);
            if (offered == self->chosen_) {
                *out = in + at + 1;
                *outLength = in[at];
                return SSL_TLSEXT_ERR_OK;
            }
        }
        return SSL_TLSEXT_ERR_NOACK;
    }

    void acceptAll()
    {
        while (running_.load()) {
            const int in = ::accept(listen_, nullptr, nullptr);
            if (in < 0) {
                return;
            }
            workers_.emplace_back([this, in]() { serve(in); });
        }
    }

    void serve(const int in)
    {
        const SslPtr session(SSL_new(context_.get()));
        CHECK(session != nullptr);
        CHECK(SSL_set_fd(session.get(), in) == 1);
        if (SSL_accept(session.get()) == 1) {
            std::string pending;
            std::vector<char> buffer(kBufferBytes);
            for (;;) {
                const int got
                    = SSL_read(session.get(), buffer.data(), static_cast<int>(buffer.size()));
                if (got <= 0) {
                    break;
                }
                pending.append(buffer.data(), static_cast<std::size_t>(got));
                std::size_t end = 0;
                while ((end = pending.find(kHeadEnd)) != std::string::npos) {
                    pending.erase(0, end + kHeadEnd.size());
                    const std::string answer(kAnswer);
                    if (SSL_write(session.get(), answer.data(), static_cast<int>(answer.size()))
                        != static_cast<int>(answer.size())) {
                        break;
                    }
                }
            }
        }
        ::close(in);
    }

    const std::string chosen_;
    const SslContextPtr context_;
    int listen_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::thread acceptor_;
    std::vector<std::thread> workers_;
    mutable std::mutex mutex_;
    std::vector<std::vector<std::uint8_t>> hellos_;
};

SocketDial dialTo(const int port)
{
    SocketDial dial;
    dial.host = kHost;
    dial.port = port;
    dial.path = "/";
    dial.tls = true;
    dial.connectTimeout = std::chrono::seconds(5);
    return dial;
}

// OpenSSL's own client in the same process: one request, one answer.
bool openSslAsks(SSL_CTX* const context, const int port)
{
    const int handle = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(handle >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = ::inet_addr(kLoopback);
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    CHECK(::connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0);
    const SslPtr session(SSL_new(context));
    CHECK(session != nullptr);
    CHECK(SSL_set_fd(session.get(), handle) == 1);
    bool answered = false;
    if (SSL_connect(session.get()) == 1) {
        const std::string request(kRequest);
        CHECK(SSL_write(session.get(), request.data(), static_cast<int>(request.size()))
            == static_cast<int>(request.size()));
        std::string got;
        std::vector<char> buffer(kBufferBytes);
        while (got.find("ok") == std::string::npos) {
            const int read
                = SSL_read(session.get(), buffer.data(), static_cast<int>(buffer.size()));
            if (read <= 0) {
                break;
            }
            got.append(buffer.data(), static_cast<std::size_t>(read));
        }
        answered = got.rfind("HTTP/1.1 200", 0) == 0;
    }
    ::close(handle);
    return answered;
}

}  // namespace

int main()
{
    // The server below writes tickets to clients that may already have hung up.
    CHECK(std::signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    const std::filesystem::path root = testutil::freshDir("chrome-tls-test");
    const tls::Credential credential = testutil::webCredential(root);

    {
        HelloServer server(credential, "http/1.1");
        const SocketDialResult refused = openSocket(dialTo(server.port()), nullptr, nullptr);
        CHECK(refused.socket == nullptr);
        const std::vector<Hello> hellos = server.hellos();
        CHECK(hellos.size() == 1);
        std::printf("websocket %s %s\n", ja4(hellos[0]).c_str(), ja3n(hellos[0]).c_str());
        CHECK(ja4(hellos[0]) == kChromeWebSocketJa4);
        CHECK(ja3n(hellos[0]) == kChromeWebSocketJa3n);
    }

    {
        HelloServer server(credential, "http/1.1");
        {
            KeptConnection page(dialTo(server.port()));
            CHECK(page.connected());
            CHECK(page.get("/", Fetch::eDocument, {}).status == 200);
        }
        {
            KeptConnection again(dialTo(server.port()));
            CHECK(again.connected());
            CHECK(again.get("/", Fetch::eImage, {}).status == 200);
        }
        CHECK(openSocket(dialTo(server.port()), nullptr, nullptr).socket == nullptr);
        const std::vector<Hello> hellos = server.hellos();
        CHECK(hellos.size() == 3);
        std::printf("page      %s %s\nresumed   %s\nwebsocket %s (resumed)\n",
            ja4(hellos[0]).c_str(), ja3n(hellos[0]).c_str(), ja4(hellos[1]).c_str(),
            ja4(hellos[2]).c_str());
        CHECK(ja4(hellos[0]) == kChromePageJa4);
        CHECK(ja3n(hellos[0]) == kChromePageJa3n);
        CHECK(hellos[0].find(kPreSharedKey) == nullptr);
        // A ticket from the first connection resumes the next one: pre_shared_key goes last.
        CHECK(hellos[1].order().back() == kPreSharedKey);
        CHECK(ja4(hellos[2]) == kChromeResumedWebSocketJa4);
        CHECK(hellos[2].order().back() == kPreSharedKey);
    }

    {
        std::set<std::vector<std::uint16_t>> orders;
        std::set<std::string> fingerprints;
        for (int fresh = 0; fresh < kFreshConnections; ++fresh) {
            HelloServer server(credential, "http/1.1");
            KeptConnection page(dialTo(server.port()));
            CHECK(page.connected());
            const Hello hello = server.hellos().at(0);
            orders.insert(hello.order());
            fingerprints.insert(ja4(hello));
        }
        CHECK(orders.size() > 1);
        CHECK(fingerprints.size() == 1);
    }

    {
        HelloServer server(credential, "h2");
        KeptConnection page(dialTo(server.port()));
        CHECK(!page.connected());
        CHECK(page.error().find("h2") != std::string::npos);
    }

    {
        HelloServer server(credential, "http/1.1");
        const SslContextPtr openSsl(SSL_CTX_new(TLS_client_method()));
        CHECK(openSsl != nullptr);
        std::atomic<int> answered{0};
        std::vector<std::thread> mixed;
        for (int thread = 0; thread < kMixedThreads; ++thread) {
            mixed.emplace_back([&]() {
                for (int round = 0; round < kMixedRounds; ++round) {
                    if (openSslAsks(openSsl.get(), server.port())) {
                        ++answered;
                    }
                    KeptConnection page(dialTo(server.port()));
                    if (page.connected() && page.get("/", Fetch::eDocument, {}).status == 200) {
                        ++answered;
                    }
                }
            });
        }
        for (std::thread& thread : mixed) {
            thread.join();
        }
        CHECK(answered.load() == 2 * kMixedThreads * kMixedRounds);
    }

    std::filesystem::remove_all(root);
    std::puts("TestChromeTls ok");
    return 0;
}
