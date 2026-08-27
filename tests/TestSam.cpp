// Bazarish project (c) 2026
#include "bazarish/Sam.hpp"

#include "TestUtil.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;

namespace {

// The golden destination from TestI2pAddress, so the address this session
// reports can be checked against a known b33.
const std::string kDestination
    = "GmVBArK-6asEg1BTOKbZ9O7c9VFbbm6g4TVPBrmuNyIcD0t-2kEJy39~dawKvPQsNJyTLK5eJi1S8jadM~z"
      "TNEpb5KHKLw6dXxgnWHw2rOVl5MXT7a96ovHhfkiaiSQQc4HIwQJhOg6hwbbhwNNs-QBLA47l5g9008tq1m"
      "Q8mhew8oiNH1ssI6vHdYkE2KdMwk1ppZ15Cyy4qe~sxAhpdvdcrJg~4VGd~flv2Zb3xQRjpcXkIWtSk0b7G"
      "6NOJm0EHXjxMFjA4LaktYebwpl1uOX-s4Qs6NMJOHUZ0JMfNUn8TYgzd70hHjXwyhnPh7Hk~cshRcI5Veh8"
      "tGU7xiEPdYezb6BSV1JalzJ7BHRqVjE6nAnlWDXZnjt1Av9USy1Kh7NvoFJXUlqXMnsEdGpWMTqcCeVYNdm"
      "eO3UC~1RLLUqHs2-gUldSWpcyewR0alYxOpwJ5Vg12Z47dQL~VEstSkf0nWn19OasjC6~ojqwvCfoe9asYV"
      "cikv94jT~PdFrxBQAEAAcAAA==";
const std::string kB33 = "a2pbgr7utvu7l5hgvsgc5p5chkylyj7ipplkyykxekjp66enh7hxiwxr.b32.i2p";
// Opaque to this layer: the client only ever hands it back to the router.
const std::string kPrivateKeys = kDestination + "cHJpdmF0ZQ==";

constexpr int kPollSliceMs = 50;
constexpr int kWaitSeconds = 20;

std::string readLine(const int fd)
{
    std::string line;
    while (true) {
        char c = 0;
        const ssize_t got = ::read(fd, &c, 1);
        if (got <= 0) {
            return line;
        }
        if (c == '\n') {
            return line;
        }
        line.push_back(c);
    }
}

void writeAll(const int fd, const std::string& text)
{
    std::size_t sent = 0;
    while (sent < text.size()) {
        const ssize_t written = ::write(fd, text.data() + sent, text.size() - sent);
        if (written <= 0) {
            return;
        }
        sent += static_cast<std::size_t>(written);
    }
}

bool contains(const std::string& text, const std::string& part)
{
    return text.find(part) != std::string::npos;
}

std::string valueOf(const std::string& line, const std::string& key)
{
    const std::size_t at = line.find(key + "=");
    if (at == std::string::npos) {
        return {};
    }
    const std::size_t from = at + key.size() + 1;
    const std::size_t to = line.find(' ', from);
    return line.substr(from, to == std::string::npos ? std::string::npos : to - from);
}

// A SAM router that answers by script. Enough of the protocol to drive the
// client through every path it has, and nothing more: no tunnels, no I2P.
class FakeRouter {
public:
    FakeRouter()
    {
        listener_ = openLoopbackListener(controlPort_);
        udp_ = openLoopbackDatagramSocket(udpPort_);
        acceptor_ = std::thread([this]() { acceptLoop(); });
    }

    ~FakeRouter()
    {
        stopping_ = true;
        ::shutdown(listener_, SHUT_RDWR);
        ::close(listener_);
        if (acceptor_.joinable()) {
            acceptor_.join();
        }
        dropConnections();
        for (std::thread& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        ::close(udp_);
    }

    FakeRouter(const FakeRouter&) = delete;
    FakeRouter& operator=(const FakeRouter&) = delete;

    sam::RouterAddress address() const
    {
        return sam::RouterAddress{"127.0.0.1", controlPort_, udpPort_};
    }

    // The reply to the next STREAM CONNECT, so a refusal can be scripted.
    void setStreamStatus(const std::string& line)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        streamStatus_ = line;
    }

    std::vector<std::string> commands() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return commands_;
    }

    std::string waitForCommand(const std::string& prefix, const int nth = 1)
    {
        for (int waited = 0; waited < kWaitSeconds * 1000 / kPollSliceMs; ++waited) {
            int seen = 0;
            for (const std::string& line : commands()) {
                if (line.rfind(prefix, 0) == 0 && ++seen == nth) {
                    return line;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(kPollSliceMs));
        }
        return {};
    }

    // Closes every live connection, which is what a router restart looks like
    // from the other side.
    void dropConnections()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const int fd : live_) {
            ::shutdown(fd, SHUT_RDWR);
        }
        live_.clear();
    }

    // Delivers one incoming stream the way STREAM FORWARD does: connect to the
    // port the client asked for, name the caller, then the payload.
    void deliverIncoming(const std::string& peer, const std::string& payload)
    {
        const std::uint16_t port = forwardPort_;
        CHECK(port != 0);
        const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        CHECK(fd >= 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
        writeAll(fd, peer + "\n" + payload);
        ::close(fd);
    }

    // One datagram as the client handed it to the router.
    std::string takeDatagram()
    {
        pollfd watched{};
        watched.fd = udp_;
        watched.events = POLLIN;
        if (::poll(&watched, 1, kWaitSeconds * 1000) <= 0) {
            return {};
        }
        std::string packet(kDatagramBufferBytes, '\0');
        const ssize_t got = ::recv(udp_, packet.data(), packet.size(), 0);
        if (got <= 0) {
            return {};
        }
        packet.resize(static_cast<std::size_t>(got));
        return packet;
    }

    // One datagram forwarded to the client, exactly as i2pd forwards it.
    void forwardDatagram(const std::string& payload)
    {
        const std::uint16_t port = clientUdpPort_;
        CHECK(port != 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        const ssize_t sent = ::sendto(udp_, payload.data(), payload.size(), 0,
            reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
        CHECK(sent == static_cast<ssize_t>(payload.size()));
    }

private:
    static constexpr std::size_t kDatagramBufferBytes = 65536;

    static int openLoopbackListener(std::uint16_t& port)
    {
        const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        CHECK(fd >= 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
        CHECK(::listen(fd, 16) == 0);
        port = boundPort(fd);
        return fd;
    }

    static int openLoopbackDatagramSocket(std::uint16_t& port)
    {
        const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(fd >= 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
        port = boundPort(fd);
        return fd;
    }

    static std::uint16_t boundPort(const int fd)
    {
        sockaddr_in bound{};
        socklen_t length = sizeof(bound);
        CHECK(::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &length) == 0);
        return ntohs(bound.sin_port);
    }

    void acceptLoop()
    {
        while (!stopping_) {
            pollfd watched{};
            watched.fd = listener_;
            watched.events = POLLIN;
            if (::poll(&watched, 1, kPollSliceMs) <= 0) {
                continue;
            }
            const int fd = ::accept(listener_, nullptr, nullptr);
            if (fd < 0) {
                continue;
            }
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                live_.push_back(fd);
                workers_.emplace_back([this, fd]() { serve(fd); });
            }
        }
    }

    void serve(const int fd)
    {
        while (!stopping_) {
            const std::string line = readLine(fd);
            if (line.empty()) {
                break;
            }
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                commands_.push_back(line);
            }
            if (line.rfind("HELLO VERSION", 0) == 0) {
                writeAll(fd, "HELLO REPLY RESULT=OK VERSION=3.3\n");
            } else if (line.rfind("SESSION CREATE", 0) == 0) {
                const std::string port = valueOf(line, "PORT");
                if (!port.empty()) {
                    clientUdpPort_ = static_cast<std::uint16_t>(std::stoi(port));
                }
                writeAll(fd, "SESSION STATUS RESULT=OK DESTINATION=" + kPrivateKeys + "\n");
            } else if (line.rfind("NAMING LOOKUP", 0) == 0) {
                writeAll(fd, "NAMING REPLY RESULT=OK NAME=ME VALUE=" + kDestination + "\n");
            } else if (line.rfind("DEST GENERATE", 0) == 0) {
                writeAll(fd, "DEST REPLY PUB=" + kDestination + " PRIV=" + kPrivateKeys + "\n");
            } else if (line.rfind("STREAM FORWARD", 0) == 0) {
                forwardPort_ = static_cast<std::uint16_t>(std::stoi(valueOf(line, "PORT")));
                writeAll(fd, "STREAM STATUS RESULT=OK\n");
            } else if (line.rfind("STREAM CONNECT", 0) == 0) {
                std::string status;
                {
                    const std::lock_guard<std::mutex> lock(mutex_);
                    status = streamStatus_;
                }
                writeAll(fd, status);
                if (status.find("RESULT=OK") == std::string::npos) {
                    break;  // a refusal closes the socket, as the router's does
                }
                echo(fd);
                break;
            } else {
                writeAll(fd, "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"unknown command\"\n");
                break;
            }
        }
        ::close(fd);
    }

    // Once a stream is up the socket carries bytes, so the far end is whatever
    // the test needs it to be: here, an echo.
    void echo(const int fd)
    {
        std::string buffer(1024, '\0');
        while (!stopping_) {
            const ssize_t got = ::read(fd, buffer.data(), buffer.size());
            if (got <= 0) {
                return;
            }
            writeAll(fd, buffer.substr(0, static_cast<std::size_t>(got)));
        }
    }

    int listener_ = -1;
    int udp_ = -1;
    std::uint16_t controlPort_ = 0;
    std::uint16_t udpPort_ = 0;
    std::atomic<std::uint16_t> forwardPort_{0};
    std::atomic<std::uint16_t> clientUdpPort_{0};
    std::atomic<bool> stopping_{false};
    std::thread acceptor_;
    mutable std::mutex mutex_;
    std::vector<std::thread> workers_;
    std::vector<int> live_;
    std::vector<std::string> commands_;
    std::string streamStatus_ = "STREAM STATUS RESULT=OK\n";
};

sam::SessionConfig streamConfig()
{
    sam::SessionConfig config;
    config.privateKeys = kPrivateKeys;
    config.style = sam::Style::eStream;
    config.leaseSet = i2p::LeaseSetKind::eEncrypted;
    config.privacy = i2p::Privacy::eMinimal;
    config.tunnelQuantity = 2;
    config.published = false;
    return config;
}

constexpr std::chrono::seconds kReady{30};
constexpr std::chrono::seconds kDial{5};
constexpr std::chrono::milliseconds kAcceptWait{5000};

void testProbe()
{
    FakeRouter router;
    // The handshake alone, which is how a client learns whether a router is there
    // at all without asking it for anything.
    CHECK(sam::probe(router.address()) == "3.3");
    CHECK(contains(router.waitForCommand("HELLO VERSION"), "MAX=3.3"));

    sam::RouterAddress nobody = router.address();
    nobody.controlPort = 1;  // nothing listens here
    bool refused = false;
    try {
        (void)sam::probe(nobody);
    } catch (const sam::Error&) {
        refused = true;
    }
    CHECK(refused);
}

void testGenerateDestination()
{
    FakeRouter router;
    const sam::Destination destination = sam::generateDestination(router.address());
    CHECK(destination.publicBase64 == kDestination);
    CHECK(destination.privateBase64 == kPrivateKeys);
    // Ed25519 is named every time: the router's own default is DSA-SHA1.
    CHECK(contains(router.waitForCommand("DEST GENERATE"), "SIGNATURE_TYPE=7"));
}

void testSessionCreate()
{
    FakeRouter router;
    const sam::Session session(router.address(), streamConfig(), kReady);

    const std::string create = router.waitForCommand("SESSION CREATE");
    CHECK(contains(create, "STYLE=STREAM"));
    CHECK(contains(create, "DESTINATION=" + kPrivateKeys));
    CHECK(contains(create, "SIGNATURE_TYPE=7"));
    CHECK(contains(create, "i2cp.leaseSetType=5"));
    // SAM publishes every destination unless told otherwise, and a dial-out
    // destination must stay out of the netDb.
    CHECK(contains(create, "i2cp.dontPublishLeaseSet=true"));
    CHECK(contains(create, "inbound.length=1"));
    CHECK(contains(create, "outbound.lengthVariance=0"));
    CHECK(contains(create, "inbound.quantity=2"));
    // A stream session takes no datagram forwarding.
    CHECK(!contains(create, "PORT="));

    CHECK(session.publicDestination() == kDestination);
    CHECK(session.privateKeys() == kPrivateKeys);
    CHECK(session.routingHost() == kB33);
    CHECK(session.alive());
}

void testConnectAndEcho()
{
    FakeRouter router;
    sam::Session session(router.address(), streamConfig(), kReady);
    const std::unique_ptr<sam::Stream> stream = session.connect(kB33, kDial);
    CHECK(stream != nullptr);

    const std::string connect = router.waitForCommand("STREAM CONNECT");
    CHECK(contains(connect, "DESTINATION=" + kB33));
    CHECK(contains(connect, "SILENT=false"));

    const std::string sent = "the frame";
    stream->writeAll(sent.data(), sent.size());
    std::string back(sent.size(), '\0');
    stream->readExact(back.data(), back.size());
    CHECK(back == sent);
}

void testRefusalCarriesItsCode()
{
    FakeRouter router;
    sam::Session session(router.address(), streamConfig(), kReady);

    router.setStreamStatus("STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE=\"LeaseSet not found\"\n");
    sam::Result unreachable = sam::Result::eOk;
    try {
        (void)session.connect(kB33, kDial);
    } catch (const sam::Error& error) {
        unreachable = error.result();
    }
    // What the caller does next hangs on this: an unreachable peer is worth
    // another attempt, a rejected key never is.
    CHECK(unreachable == sam::Result::eCantReachPeer);

    router.setStreamStatus("STREAM STATUS RESULT=INVALID_KEY\n");
    sam::Result badKey = sam::Result::eOk;
    try {
        (void)session.connect(kB33, kDial);
    } catch (const sam::Error& error) {
        badKey = error.result();
    }
    CHECK(badKey == sam::Result::eInvalidKey);
}

void testForwardedAccept()
{
    FakeRouter router;
    sam::Session session(router.address(), streamConfig(), kReady);
    session.listen();

    const std::string forward = router.waitForCommand("STREAM FORWARD");
    CHECK(contains(forward, "HOST=127.0.0.1"));
    CHECK(contains(forward, "SILENT=false"));

    const std::string payload = "hello from the other side";
    router.deliverIncoming(kDestination, payload);

    std::string peer;
    const std::unique_ptr<sam::Stream> stream = session.accept(peer, kAcceptWait);
    CHECK(stream != nullptr);
    CHECK(peer == kDestination);
    std::string body(payload.size(), '\0');
    stream->readExact(body.data(), body.size());
    CHECK(body == payload);

    // Nothing arriving is a timeout, not a failure.
    std::string nobody;
    CHECK(session.accept(nobody, std::chrono::milliseconds(100)) == nullptr);
}

void testRawDatagrams()
{
    FakeRouter router;
    sam::SessionConfig config = streamConfig();
    config.style = sam::Style::eRaw;
    config.published = true;
    sam::Session session(router.address(), config, kReady);

    const std::string create = router.waitForCommand("SESSION CREATE");
    CHECK(contains(create, "STYLE=RAW"));
    CHECK(contains(create, "HOST=127.0.0.1"));
    CHECK(contains(create, "PORT="));
    CHECK(!contains(create, "dontPublishLeaseSet"));

    const std::string payload = "audio frame";
    session.sendDatagram(kB33, payload.data(), payload.size());
    const std::string handed = router.takeDatagram();
    // Version, session and destination on one line, then the payload.
    CHECK(handed.rfind("3.0 ", 0) == 0);
    CHECK(contains(handed, " " + kB33 + "\n" + payload));

    // Raw forwarding carries the payload and nothing else.
    router.forwardDatagram(payload);
    const std::vector<std::uint8_t> received
        = session.receiveDatagram(nullptr, std::chrono::milliseconds(5000));
    CHECK(std::string(received.begin(), received.end()) == payload);
}

void testRepliableDatagrams()
{
    FakeRouter router;
    sam::SessionConfig config = streamConfig();
    config.style = sam::Style::eDatagram;
    sam::Session session(router.address(), config, kReady);
    CHECK(contains(router.waitForCommand("SESSION CREATE"), "STYLE=DATAGRAM"));

    const std::string payload = "a repliable line";
    router.forwardDatagram(kDestination + "\n" + payload);
    std::string peer;
    const std::vector<std::uint8_t> received
        = session.receiveDatagram(&peer, std::chrono::milliseconds(5000));
    CHECK(peer == kDestination);
    CHECK(std::string(received.begin(), received.end()) == payload);
}

void testSessionComesBackAfterTheRouterDoes()
{
    FakeRouter router;
    sam::Session session(router.address(), streamConfig(), kReady);
    session.listen();
    CHECK(router.waitForCommand("SESSION CREATE", 1) != "");

    // The router drops everything, which is what a restart looks like here.
    router.dropConnections();

    // The session rebuilds itself from the keys it holds, so the address is the
    // one peers already have - and accepting resumes with it.
    CHECK(router.waitForCommand("SESSION CREATE", 2) != "");
    CHECK(router.waitForCommand("STREAM FORWARD", 2) != "");
    for (int waited = 0; waited < kWaitSeconds * 1000 / kPollSliceMs && !session.alive();
         ++waited) {
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollSliceMs));
    }
    CHECK(session.alive());
    CHECK(session.publicDestination() == kDestination);
}

void testRefusesWhatIsNotLoopback()
{
    sam::RouterAddress elsewhere;
    elsewhere.host = "10.0.0.1";
    bool refused = false;
    try {
        (void)sam::generateDestination(elsewhere);
    } catch (const sam::Error&) {
        refused = true;
    }
    // The router is handed private keys; that is a loopback-only conversation.
    CHECK(refused);
}

void testRefusesAnEndlessReply()
{
    // A router that answers with a line that never ends must not be able to
    // decide how much memory this process spends.
    std::uint16_t port = 0;
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::bind(listener, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
    CHECK(::listen(listener, 1) == 0);
    sockaddr_in bound{};
    socklen_t length = sizeof(bound);
    CHECK(::getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &length) == 0);
    port = ntohs(bound.sin_port);

    std::atomic<bool> stop{false};
    std::thread flooder([listener, &stop]() {
        const int fd = ::accept(listener, nullptr, nullptr);
        if (fd < 0) {
            return;
        }
        const std::string chunk(4096, 'x');
        while (!stop) {
            if (::write(fd, chunk.data(), chunk.size()) <= 0) {
                break;
            }
        }
        ::close(fd);
    });

    sam::RouterAddress flooding;
    flooding.controlPort = port;
    bool refused = false;
    try {
        (void)sam::generateDestination(flooding);
    } catch (const sam::Error&) {
        refused = true;
    }
    stop = true;
    flooder.join();
    ::close(listener);
    CHECK(refused);
}

}  // namespace

int main()
{
    testProbe();
    testGenerateDestination();
    testSessionCreate();
    testConnectAndEcho();
    testRefusalCarriesItsCode();
    testForwardedAccept();
    testRawDatagrams();
    testRepliableDatagrams();
    testSessionComesBackAfterTheRouterDoes();
    testRefusesWhatIsNotLoopback();
    testRefusesAnEndlessReply();
    std::printf("TestSam ok\n");
    return 0;
}
