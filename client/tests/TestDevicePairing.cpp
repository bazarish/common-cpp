// Bazarish project (c) 2026
#include "DevicePairing.hpp"
#include "I2pRouter.hpp"

#include "TestUtil.hpp"

#include <csignal>
#include <filesystem>
#include <fstream>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <exception>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace {

class FakeStream {
public:
    FakeStream(const int fd, std::atomic<std::size_t>* const pending)
        : fd_(fd)
        , pending_(pending)
    {
    }
    FakeStream(FakeStream&& other) noexcept : fd_(other.fd_), pending_(other.pending_)
    {
        other.fd_ = -1;
    }
    ~FakeStream() { close(); }
    FakeStream(const FakeStream&) = delete;
    FakeStream& operator=(const FakeStream&) = delete;

    void setReadTimeout(std::chrono::seconds) {}

    std::size_t readSome(void* const buffer, const std::size_t size)
    {
        const ssize_t got = ::read(fd_, buffer, size);
        return got > 0 ? static_cast<std::size_t>(got) : 0;
    }

    void writeAll(const void* const data, const std::size_t size)
    {
        const char* const bytes = static_cast<const char*>(data);
        std::size_t done = 0;
        while (done < size) {
            const ssize_t put = ::write(fd_, bytes + done, size - done);
            if (put <= 0) {
                throw std::runtime_error("fake stream: the other end is gone");
            }
            done += static_cast<std::size_t>(put);
        }
    }

    std::size_t pendingBytes() const { return pending_ == nullptr ? 0 : pending_->load(); }

    void close()
    {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_;
    std::atomic<std::size_t>* pending_;
};

class FakeEndpoint {
public:
    explicit FakeEndpoint(std::atomic<bool>* const stopWhenEmpty)
        : stopWhenEmpty_(stopWhenEmpty)
    {
    }

    void queue(std::unique_ptr<FakeStream> stream) { waiting_.push_back(std::move(stream)); }

    std::unique_ptr<FakeStream> accept(std::string& peer, std::chrono::seconds)
    {
        peer = "fake-peer";
        if (taken_ >= waiting_.size()) {
            if (stopWhenEmpty_ != nullptr) {
                stopWhenEmpty_->store(true);
            }
            return nullptr;
        }
        return std::move(waiting_[taken_++]);
    }

    bool waitReady(std::chrono::seconds) const { return ready; }

    std::unique_ptr<FakeStream> connect(const std::string&, std::chrono::seconds)
    {
        return accept(dialled_, std::chrono::seconds(0));
    }

    bool ready = true;

private:
    std::vector<std::unique_ptr<FakeStream>> waiting_;
    std::size_t taken_ = 0;
    std::atomic<bool>* stopWhenEmpty_;
    std::string dialled_;
};

std::vector<int> g_peerFds;

int wireInto(FakeEndpoint& endpoint, std::atomic<std::size_t>* const pending = nullptr)
{
    int fds[2] = {-1, -1};
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    endpoint.queue(std::make_unique<FakeStream>(fds[0], pending));
    g_peerFds.push_back(fds[1]);
    return fds[1];
}

void writeTo(const int fd, const std::string& text)
{
    std::size_t done = 0;
    while (done < text.size()) {
        const ssize_t put = ::write(fd, text.data() + done, text.size() - done);
        CHECK(put > 0);
        done += static_cast<std::size_t>(put);
    }
}

std::string readHeadFrom(const int fd)
{
    std::string raw;
    std::array<char, 1024> buffer{};
    while (raw.find("\r\n\r\n") == std::string::npos) {
        const ssize_t got = ::read(fd, buffer.data(), buffer.size());
        if (got <= 0) {
            return raw;
        }
        raw.append(buffer.data(), static_cast<std::size_t>(got));
    }
    return raw;
}

std::size_t readBodyFrom(const int fd, const std::size_t expected, std::string& body)
{
    std::vector<char> buffer(kPairChunkBytes);
    while (body.size() < expected) {
        const ssize_t got = ::read(fd, buffer.data(), buffer.size());
        if (got <= 0) {
            break;
        }
        body.append(buffer.data(), static_cast<std::size_t>(got));
    }
    return body.size();
}

Bytes patternOf(const std::size_t size)
{
    Bytes made(size);
    for (std::size_t at = 0; at < size; ++at) {
        made[at] = static_cast<unsigned char>(at % 251);
    }
    return made;
}

std::string requestWith(const std::string& code)
{
    return pairRequest("pair.b32.i2p", code);
}

int cannedInto(FakeEndpoint& endpoint, const std::string& answer, const bool eof)
{
    const int peer = wireInto(endpoint);
    writeTo(peer, answer);
    if (eof) {
        CHECK(::shutdown(peer, SHUT_WR) == 0);
    }
    return peer;
}

}  // namespace

int main()
{
    ::signal(SIGPIPE, SIG_IGN);
    const std::string code = "4071";
    std::atomic<int> refusals{0};
    const PairRefusedFn countWrong = [&refusals](const int seen) { refusals.store(seen); };
    const Bytes bundle = patternOf(1000);

    {
        std::set<std::string> drawn;
        for (int draw = 0; draw < 2000; ++draw) {
            const std::string one = newPairCode();
            CHECK(one.size() == kPairCodeDigits);
            CHECK(isPairCode(one));
            drawn.insert(one);
        }
        CHECK(drawn.size() > 1000);

        CHECK(isPairCode("0000"));
        CHECK(!isPairCode("123"));
        CHECK(!isPairCode("12345"));
        CHECK(!isPairCode("12a4"));
        CHECK(!isPairCode(""));
        CHECK(!isPairCode(" 123"));
    }

    {
        const std::map<std::string, std::string> right{{"x-bazarish-pair", code}};
        const std::map<std::string, std::string> wrong{{"x-bazarish-pair", "0000"}};
        const std::map<std::string, std::string> none{{"host", "pair.b32.i2p"}};

        CHECK(pairVerdict("GET", "/hello", right, code).status == kI2pHttpOk);
        CHECK(!pairVerdict("GET", "/hello", right, code).counted);
        CHECK(pairVerdict("GET", "/hello", wrong, code).status == kI2pHttpForbidden);
        CHECK(pairVerdict("GET", "/hello", wrong, code).counted);
        CHECK(pairVerdict("GET", "/hello", none, code).status == kI2pHttpBadRequest);
        CHECK(!pairVerdict("GET", "/hello", none, code).counted);
        CHECK(pairVerdict("GET", "/other", right, code).status == kI2pHttpNotFound);
        CHECK(!pairVerdict("GET", "/other", right, code).counted);
        CHECK(pairVerdict("POST", "/hello", right, code).status == kI2pHttpNotFound);
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(&cancel);
        const int refused = wireInto(endpoint);
        const int accepted = wireInto(endpoint);

        PairServeResult result;
        std::thread serving([&]() {
            result = servePairBundle(endpoint, bundle, code, nullptr, countWrong, cancel);
        });

        writeTo(refused, requestWith("0000"));
        const std::string refusal = readHeadFrom(refused);
        CHECK(refusal.find("403 Forbidden") != std::string::npos);
        CHECK(refusal.find("X-Bazarish-Pair-Left: 9") != std::string::npos);

        writeTo(accepted, requestWith(code));
        const std::string head = readHeadFrom(accepted);
        CHECK(head.find("200 OK") != std::string::npos);
        CHECK(head.find("Content-Length: 1000") != std::string::npos);
        std::string body = head.substr(head.find("\r\n\r\n") + 4);
        CHECK(readBodyFrom(accepted, bundle.size(), body) == bundle.size());
        CHECK(Bytes(body.begin(), body.end()) == bundle);
        ::shutdown(accepted, SHUT_WR);

        serving.join();
        CHECK(result.delivered);
        CHECK(result.wrongCodes == 1);
        CHECK(refusals.load() == 1);
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(&cancel);
        std::vector<int> guessers;
        for (int guess = 0; guess < kMaxWrongCodes; ++guess) {
            guessers.push_back(wireInto(endpoint));
        }
        const int tooLate = wireInto(endpoint);

        PairServeResult result;
        std::thread serving([&]() {
            result = servePairBundle(endpoint, bundle, code, nullptr, countWrong, cancel);
        });

        for (int guess = 0; guess < kMaxWrongCodes; ++guess) {
            writeTo(guessers[static_cast<std::size_t>(guess)], requestWith("0000"));
            const std::string refusal = readHeadFrom(guessers[static_cast<std::size_t>(guess)]);
            CHECK(refusal.find("403 Forbidden") != std::string::npos);
            CHECK(refusal.find("X-Bazarish-Pair-Left: "
                      + std::to_string(kMaxWrongCodes - guess - 1))
                != std::string::npos);
        }

        serving.join();
        CHECK(!result.delivered);
        CHECK(result.wrongCodes == kMaxWrongCodes);
        CHECK(refusals.load() == kMaxWrongCodes);

        writeTo(tooLate, requestWith(code));
        std::array<char, 64> unanswered{};
        CHECK(::recv(tooLate, unanswered.data(), unanswered.size(), MSG_DONTWAIT) < 0);
    }

    {
        std::atomic<bool> cancel{false};
        std::atomic<std::size_t> pending{kPairQueuedBytesCap + 1};
        FakeEndpoint endpoint(&cancel);
        const int reader = wireInto(endpoint, &pending);
        const Bytes big = patternOf(2 * kPairChunkBytes + 1);

        PairServeResult result;
        std::thread serving([&]() {
            result = servePairBundle(endpoint, big, code, nullptr, nullptr, cancel);
        });

        writeTo(reader, requestWith(code));
        const std::string head = readHeadFrom(reader);
        CHECK(head.find("Content-Length: " + std::to_string(big.size())) != std::string::npos);
        std::string body = head.substr(head.find("\r\n\r\n") + 4);

        std::this_thread::sleep_for(std::chrono::seconds(1));
        CHECK(body.size() < big.size());

        pending.store(0);
        CHECK(readBodyFrom(reader, big.size(), body) == big.size());
        CHECK(Bytes(body.begin(), body.end()) == big);
        ::shutdown(reader, SHUT_WR);

        serving.join();
        CHECK(result.delivered);
    }

    {
        std::atomic<bool> cancel{false};
        std::atomic<std::size_t> pending{kPairQueuedBytesCap + 1};
        FakeEndpoint endpoint(&cancel);
        const int reader = wireInto(endpoint, &pending);

        PairServeResult result;
        std::thread serving([&]() {
            result = servePairBundle(endpoint, patternOf(2 * kPairChunkBytes), code, nullptr,
                nullptr, cancel);
        });

        writeTo(reader, requestWith(code));
        CHECK(!readHeadFrom(reader).empty());
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        cancel.store(true);

        serving.join();
        CHECK(!result.delivered);
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(&cancel);
        const int broken = wireInto(endpoint);
        const int good = wireInto(endpoint);

        PairServeResult result;
        std::thread serving([&]() {
            result = servePairBundle(endpoint, bundle, code, nullptr, countWrong, cancel);
        });

        ::shutdown(broken, SHUT_WR);
        writeTo(good, requestWith(code));
        const std::string head = readHeadFrom(good);
        CHECK(head.find("200 OK") != std::string::npos);
        std::string body = head.substr(head.find("\r\n\r\n") + 4);
        CHECK(readBodyFrom(good, bundle.size(), body) == bundle.size());
        ::shutdown(good, SHUT_WR);

        serving.join();
        CHECK(result.delivered);
        CHECK(result.wrongCodes == 0);
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(nullptr);
        (void)cannedInto(endpoint, pairRefusal(kI2pHttpForbidden, 7), false);
        const PairFetchResult refused
            = fetchPairBundle(endpoint, "pair.b32.i2p", "0000", nullptr, cancel);
        CHECK(refused.wrongCode);
        CHECK(refused.triesLeft == 7);
        CHECK(refused.bundle.empty());
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(nullptr);
        (void)cannedInto(endpoint, buildI2pHttpResponse(kI2pHttpForbidden, {}, 0), false);
        CHECK_THROWS(fetchPairBundle(endpoint, "pair.b32.i2p", "0000", nullptr, cancel));
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(nullptr);
        const std::string body(bundle.begin(), bundle.end());
        (void)cannedInto(endpoint, pairBundleHead(bundle.size()) + body, true);
        const PairFetchResult got
            = fetchPairBundle(endpoint, "pair.b32.i2p", code, nullptr, cancel);
        CHECK(!got.wrongCode);
        CHECK(got.bundle == bundle);
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(nullptr);
        const Bytes big = patternOf(3 * kPairChunkBytes);
        const std::string body(big.begin(), big.end());
        (void)cannedInto(endpoint, pairBundleHead(big.size()) + body, true);
        std::uint64_t lastSeen = 0;
        const PairProgressFn watch
            = [&lastSeen](const std::uint64_t done, const std::uint64_t) { lastSeen = done; };
        const PairFetchResult got
            = fetchPairBundle(endpoint, "pair.b32.i2p", code, watch, cancel);
        CHECK(got.bundle == big);
        CHECK(lastSeen == big.size());
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(nullptr);
        (void)cannedInto(endpoint, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nxyz", true);
        CHECK_THROWS(fetchPairBundle(endpoint, "pair.b32.i2p", code, nullptr, cancel));
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(nullptr);
        (void)cannedInto(endpoint, pairBundleHead(kMaxPairBundleBytes + 1), false);
        CHECK_THROWS(fetchPairBundle(endpoint, "pair.b32.i2p", code, nullptr, cancel));
        (void)cannedInto(endpoint, pairBundleHead(0), false);
        CHECK_THROWS(fetchPairBundle(endpoint, "pair.b32.i2p", code, nullptr, cancel));
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(nullptr);
        (void)cannedInto(endpoint, pairBundleHead(bundle.size()) + "ten-bytes!", true);
        std::string said;
        try {
            (void)fetchPairBundle(endpoint, "pair.b32.i2p", code, nullptr, cancel);
        } catch (const std::exception& error) {
            said = error.what();
        }
        CHECK(said.find("closed after 10 of 1000 bytes") != std::string::npos);
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(nullptr);
        endpoint.ready = false;
        CHECK_THROWS(fetchPairBundle(endpoint, "pair.b32.i2p", code, nullptr, cancel));
    }

    {
        std::atomic<bool> cancel{false};
        FakeEndpoint endpoint(nullptr);
        CHECK_THROWS(fetchPairBundle(endpoint, "pair.b32.i2p", code, nullptr, cancel));
    }

    {
        const std::filesystem::path dir
            = std::filesystem::temp_directory_path() / "bazarish-pair-reseed";
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);

        CHECK(!applyLinkReseed(dir, {}));
        CHECK(reseedUrls().empty());

        CHECK(applyLinkReseed(dir, {"https://seed.example/"}));
        CHECK(reseedUrls().size() == 1);
        CHECK(reseedUrls()[0] == "https://seed.example/");

        std::filesystem::create_directories(dir / "netDb" / "r0");
        for (std::size_t made = 0; made < kMinKnownRouters; ++made) {
            std::ofstream out(dir / "netDb" / "r0" / ("routerInfo-" + std::to_string(made)));
            CHECK(out.good());
        }
        CHECK(!applyLinkReseed(dir, {"https://other.example/"}));
        CHECK(reseedUrls()[0] == "https://seed.example/");

        std::filesystem::remove_all(dir);
    }

    for (const int fd : g_peerFds) {
        ::close(fd);
    }

    std::puts("TestDevicePairing passed");
    return 0;
}
