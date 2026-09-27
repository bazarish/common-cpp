// Bazarish project (c) 2026
#include <bazarish/FederationFrame.hpp>

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>

using namespace bazarish;

namespace {

// One end of a socket pair, with the two methods the frame needs. The whole
// point of the frame being a template: this stands in for an I2P stream.
class SocketStream {
public:
    explicit SocketStream(const int fd)
        : fd_(fd)
    {
    }
    ~SocketStream() { ::close(fd_); }
    SocketStream(const SocketStream&) = delete;
    SocketStream& operator=(const SocketStream&) = delete;

    void readExact(void* const buffer, const std::size_t size)
    {
        auto* const out = static_cast<std::uint8_t*>(buffer);
        std::size_t got = 0;
        while (got < size) {
            const ssize_t n = ::read(fd_, out + got, size - got);
            if (n <= 0) {
                throw std::runtime_error("socket closed before readExact completed");
            }
            got += static_cast<std::size_t>(n);
        }
    }

    void writeAll(const void* const data, const std::size_t size)
    {
        const auto* const in = static_cast<const std::uint8_t*>(data);
        std::size_t off = 0;
        while (off < size) {
            const ssize_t n = ::write(fd_, in + off, size - off);
            if (n <= 0) {
                throw std::runtime_error("socket closed before writeAll completed");
            }
            off += static_cast<std::size_t>(n);
        }
    }

private:
    const int fd_;
};

// A deliver payload big enough that it cannot ride inside the header line.
constexpr std::size_t kPayloadBytes = 4096;

}  // namespace

int main()
{
    // The deliver header names the envelope and the payload length that follows.
    {
        const Bytes sealed{1, 2, 3, 4};
        const nlohmann::json header
            = nlohmann::json::parse(buildFederationDeliverHeader(sealed, kPayloadBytes));
        CHECK(header.at("op") == "deliver");
        CHECK(fromBase64(header.at("sealed").get<std::string>()) == sealed);
        CHECK(header.at("len") == kPayloadBytes);
    }

    // A signed confirmation comes back whole.
    {
        const nlohmann::json reply = {{"delivered", true}, {"deliveryId", "abc123"},
            {"signerPub", toBase64(Bytes{7, 7})}, {"sig", toBase64(Bytes{9, 9, 9})}};
        const FederationDeliverResult parsed = parseFederationDeliverReply(reply.dump());
        CHECK(parsed.delivered);
        CHECK(parsed.deliveryId == "abc123");
        CHECK((parsed.signerPublicDer == Bytes{7, 7}));
        CHECK((parsed.signature == Bytes{9, 9, 9}));
        CHECK(parsed.errorCode.empty());
    }

    // A refusal carries its typed reason and no confirmation.
    {
        const nlohmann::json reply = {{"delivered", false}, {"errorCode", "DELIVERY_REJECTED"},
            {"errorMessage", "delivery rejected"}};
        const FederationDeliverResult parsed = parseFederationDeliverReply(reply.dump());
        CHECK(!parsed.delivered);
        CHECK(parsed.errorCode == "DELIVERY_REJECTED");
        CHECK(parsed.errorMessage == "delivery rejected");
        CHECK(parsed.signature.empty());
    }

    // The fetch frame, both ways.
    {
        const Bytes sealed{5, 6};
        const nlohmann::json header
            = nlohmann::json::parse(buildFederationFetchHeader("card", sealed));
        CHECK(header.at("op") == "card");
        CHECK(fromBase64(header.at("sealed").get<std::string>()) == sealed);

        const FederationFetchResult ok = parseFederationFetchReply(
            nlohmann::json({{"ok", true}, {"sealed", toBase64(Bytes{8})}}).dump());
        CHECK(ok.ok);
        CHECK(ok.sealed == Bytes{8});

        const FederationFetchResult unknown = parseFederationFetchReply(
            nlohmann::json({{"ok", false}, {"errorCode", "CARD_UNKNOWN"}}).dump());
        CHECK(!unknown.ok);
        CHECK(unknown.errorCode == "CARD_UNKNOWN");
    }

    // A header line with no end to it is refused rather than grown without
    // bound: what arrives is a peer's say-so, not this process's.
    {
        int fds[2];
        CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        SocketStream reader(fds[0]);
        SocketStream writer(fds[1]);
        std::thread flood([&writer]() {
            const std::string chunk(kPayloadBytes, 'x');
            try {
                for (std::size_t sent = 0; sent <= kMaxFederationHeaderLineBytes;
                    sent += chunk.size()) {
                    writer.writeAll(chunk.data(), chunk.size());
                }
            } catch (const std::exception&) {
                // The reader gave up and closed: that is the case under test.
            }
        });
        bool refused = false;
        try {
            (void)detail::readFederationHeaderLine(reader);
        } catch (const std::exception&) {
            refused = true;
        }
        CHECK(refused);
        flood.join();
    }

    // And the whole exchange over a pair of sockets: header out, payload out,
    // one line back.
    {
        int fds[2];
        CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        SocketStream server(fds[0]);
        SocketStream client(fds[1]);
        const Bytes sealed{0x11, 0x22};
        const Bytes payload(kPayloadBytes, 0x33);

        std::thread peer([&server, &payload]() {
            const nlohmann::json header
                = nlohmann::json::parse(detail::readFederationHeaderLine(server));
            CHECK(header.at("len") == payload.size());
            Bytes received(header.at("len").get<std::size_t>());
            server.readExact(received.data(), received.size());
            CHECK(received == payload);
            detail::writeFederationHeaderLine(server,
                nlohmann::json({{"delivered", true}, {"deliveryId", "round-trip"}}).dump());
        });
        const FederationDeliverResult result = federationSendDeliver(client, sealed, payload);
        peer.join();
        CHECK(result.delivered);
        CHECK(result.deliveryId == "round-trip");
    }

    std::printf("TestFederationFrame ok\n");
    return 0;
}
