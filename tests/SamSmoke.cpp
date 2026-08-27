// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "TestUtil.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

// End-to-end over a live I2P router reached by SAM (not a unit test - needs a
// running i2pd and the network). Two destinations of this process talk to each
// other through I2P: one accepts, the other dials.
//
//   sam_smoke [host] [control port] [rebuild|b33|b33-cold]
//
// Datagrams are addressed by the peer's base64 destination, which every router
// takes. Addressing one by its ".b32.i2p" host is asked for by name: "b33" after
// the stream test, "b33-cold" instead of it. The two differ because opening a
// stream to a host puts it in the router's addressbook, and a router that cannot
// resolve a blinded address on its own will still find it there afterwards.

using namespace bazarish;

namespace {

constexpr auto kReady = std::chrono::seconds(300);
constexpr auto kDial = std::chrono::seconds(180);
constexpr auto kAcceptWait = std::chrono::seconds(180);
constexpr auto kDatagramWait = std::chrono::milliseconds(60000);
constexpr int kTunnelQuantity = 2;

i2p::EndpointConfig destinationFor(i2p::Router& router, const bool published,
    const std::string& label)
{
    i2p::EndpointConfig config{router.generateKeys()};
    config.leaseSet = i2p::LeaseSetKind::eEncrypted;
    config.privacy = i2p::Privacy::eMinimal;
    config.tunnelQuantity = kTunnelQuantity;
    config.published = published;
    config.label = label;
    return config;
}

}  // namespace

int main(int argc, char** argv)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eSam;
    if (argc > 1) {
        config.samHost = argv[1];
    }
    if (argc > 2) {
        config.samControlPort = std::stoi(argv[2]);
    }

    i2p::Router router(config);
    std::printf("router: running=%d ready=%d\n", router.running() ? 1 : 0,
        router.ready() ? 1 : 0);
    CHECK(router.running());
    CHECK(router.ready());

    // An external router answers none of these, and says so rather than
    // returning a zero that reads like a fact.
    const i2p::Capabilities what = router.capabilities();
    CHECK(!what.routerCounters);
    CHECK(!what.netDbSample);
    CHECK(!what.proxy);
    CHECK(!what.offlineKeys);
    CHECK_THROWS(router.knownRouters());
    CHECK_THROWS(router.proxyState());

    const i2p::Keys keys = router.generateKeys();
    CHECK(!keys.publicBase64().empty());
    CHECK(keys.base32().size() == 52);
    std::printf("generated destination: %s.b32.i2p\n", keys.base32().c_str());

    std::printf("building two destinations (tunnels take a while)...\n");
    const std::shared_ptr<i2p::Endpoint> server
        = router.createEndpoint(destinationFor(router, true, "smoke server"));
    const std::shared_ptr<i2p::Endpoint> client
        = router.createEndpoint(destinationFor(router, false, "smoke client"));
    CHECK(server->waitReady(kReady));
    CHECK(client->waitReady(kReady));
    std::printf("server is %s\nclient is up\n", server->routingHost().c_str());

    // The status view is this process's own bookkeeping, which an external
    // router does not take away.
    const std::vector<i2p::LocalDestination> destinations = router.localDestinations();
    CHECK(destinations.size() == 2);

    // Addressing a datagram by the host peers actually know, rather than by a
    // destination in full. A repliable one also names its sender back.
    const auto datagramsByHost = [&]() {
        const std::string toHost = "one raw datagram, addressed by host";
        client->sendRawDatagram(server->routingHost(), toHost.data(), toHost.size());
        const std::vector<std::uint8_t> byHost = server->receiveRawDatagram(kDatagramWait);
        CHECK(std::string(byHost.begin(), byHost.end()) == toHost);
        std::printf("raw datagram to %s: %zu bytes\n", server->routingHost().c_str(),
            byHost.size());

        const std::string repliable = "one repliable datagram";
        client->sendDatagram(server->routingHost(), repliable.data(), repliable.size());
        std::string sender;
        const std::vector<std::uint8_t> answered = server->receiveDatagram(sender, kDatagramWait);
        CHECK(std::string(answered.begin(), answered.end()) == repliable);
        CHECK(sender == client->publicBase64());
        std::printf("repliable datagram: %zu bytes, sender identified\n", answered.size());
    };

    const std::string mode = argc > 3 ? argv[3] : std::string();
    if (mode == "b33-cold") {
        // Nothing has dialled this host, so the router has to resolve the
        // blinded address itself.
        datagramsByHost();
        std::printf("SamSmoke ok\n");
        return 0;
    }

    const std::string sent = "one frame over I2P";
    std::string received;
    std::string caller;
    std::string acceptFailure;
    std::thread accepting([&]() {
        // Whatever goes wrong on this side is reported rather than thrown out of
        // a thread, where it would only abort the process and say nothing.
        try {
            const std::unique_ptr<i2p::Stream> stream = server->accept(caller, kAcceptWait);
            if (stream == nullptr) {
                acceptFailure = "nothing arrived";
                return;
            }
            received.resize(sent.size());
            stream->readExact(received.data(), received.size());
            stream->writeAll(received.data(), received.size());
        } catch (const std::exception& error) {
            acceptFailure = error.what();
        }
    });

    std::string dialFailure;
    try {
        const std::unique_ptr<i2p::Stream> stream
            = client->connect(server->routingHost(), kDial);
        CHECK(stream != nullptr);
        stream->writeAll(sent.data(), sent.size());
        std::string echoed(sent.size(), '\0');
        stream->readExact(echoed.data(), echoed.size());
        CHECK(echoed == sent);
    } catch (const std::exception& error) {
        dialFailure = error.what();
    }
    accepting.join();
    if (!acceptFailure.empty() || !dialFailure.empty()) {
        std::printf("stream failed: accepting=[%s] dialling=[%s]\n", acceptFailure.c_str(),
            dialFailure.c_str());
    }
    CHECK(acceptFailure.empty());
    CHECK(dialFailure.empty());

    CHECK(received == sent);
    CHECK(caller == client->publicBase64());
    std::printf("stream: %zu bytes there and back, caller identified\n", sent.size());

    const std::string frame = "one raw datagram";
    client->sendRawDatagram(server->publicBase64(), frame.data(), frame.size());
    const std::vector<std::uint8_t> arrived = server->receiveRawDatagram(kDatagramWait);
    CHECK(std::string(arrived.begin(), arrived.end()) == frame);
    std::printf("raw datagram: %zu bytes\n", arrived.size());

    if (mode == "b33") {
        datagramsByHost();
    }

    // With "rebuild" as the third argument, the run pauses here so the router can
    // be restarted under it: the session is the router's, and losing it must cost
    // the destination its streams but not its address.
    if (mode == "rebuild") {
        const std::string address = server->routingHost();
        std::printf("waiting for a router restart\n");
        std::fflush(stdout);
        const auto deadline = std::chrono::steady_clock::now() + kReady;
        while (server->ready() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        CHECK(!server->ready());
        std::printf("the router went away; waiting for the session to come back\n");
        CHECK(server->waitReady(kReady));
        CHECK(client->waitReady(kReady));
        CHECK(server->routingHost() == address);

        std::string peer;
        std::thread again([&]() {
            const std::unique_ptr<i2p::Stream> incoming = server->accept(peer, kAcceptWait);
            if (incoming == nullptr) {
                return;
            }
            std::string body(sent.size(), '\0');
            incoming->readExact(body.data(), body.size());
            incoming->writeAll(body.data(), body.size());
        });
        const std::unique_ptr<i2p::Stream> reopened
            = client->connect(server->routingHost(), kDial);
        CHECK(reopened != nullptr);
        reopened->writeAll(sent.data(), sent.size());
        std::string back(sent.size(), '\0');
        reopened->readExact(back.data(), back.size());
        again.join();
        CHECK(back == sent);
        std::printf("same address after the restart, and it streams again\n");
    }

    std::printf("SamSmoke ok\n");
    return 0;
}
