// Bazarish project (c) 2026
//
// End-to-end smoke for bazarish::i2p over live I2P, through the wrapper ONLY -
// this translation unit includes no i2pd or Boost header. Brings up the embedded
// router, an offline-transient SERVER endpoint and a CLIENT endpoint, then does a
// stream round-trip, a datagram round-trip, and an in-process offline-signature
// refresh. Not a unit test (needs the network); run manually.
#include <bazarish/I2p.hpp>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <thread>

using namespace std::chrono;

int main(int argc, char** argv)
{
    const std::string dataDir = argc > 1 ? argv[1] : "/tmp/baz-i2p-smoke";

    bazarish::i2p::Router router(bazarish::i2p::RouterConfig{dataDir, bazarish::i2p::Role::eClient});
    std::printf("[smoke] waiting for router...\n");
    router.waitReady(seconds(300));
    std::printf("[smoke] router ready=%d knownRouters=%d\n", router.ready(), router.knownRouters());

    // Offline-transient server endpoint (standard LS -> plain b32 address).
    const auto master = bazarish::i2p::Keys::generate();
    const auto transient = master.issueTransient(static_cast<std::int64_t>(std::time(nullptr)) + 3600);
    bazarish::i2p::EndpointConfig serverCfg{
        transient, bazarish::i2p::LeaseSetKind::eStandard, bazarish::i2p::Privacy::eMax, 3, true};
    bazarish::i2p::EndpointConfig clientCfg{
        bazarish::i2p::Keys::generate(), bazarish::i2p::LeaseSetKind::eStandard,
        bazarish::i2p::Privacy::eMax, 3, true};
    auto server = router.createEndpoint(serverCfg);
    auto client = router.createEndpoint(clientCfg);
    std::printf("[smoke] server addr=%s offline=%d sameAddr=%d\n",
        server->routingHost().c_str(), transient.isOffline(),
        transient.base32() == master.base32());

    const bool sr = server->waitReady(seconds(300));
    const bool cr = client->waitReady(seconds(300));
    std::printf("[smoke] ready server=%d client=%d\n", sr, cr);

    std::thread streamEcho([&] {
        std::string peer;
        auto s = server->accept(peer, seconds(300));
        if (!s) { return; }
        char buf[256];
        const std::size_t n = s->readSome(buf, sizeof buf);
        s->writeAll(buf, n);
        s->close();
    });
    std::thread datagramEcho([&] {
        std::string peer;
        auto payload = server->receiveDatagram(peer, milliseconds(300000));
        if (!payload.empty()) { server->sendDatagram(peer, payload.data(), payload.size()); }
    });

    std::string streamResult = "<none>";
    if (auto cs = client->connect(server->routingHost(), seconds(240)))
    {
        const std::string ping = "wrapper-stream-ping";
        cs->writeAll(ping.data(), ping.size());
        char buf[256];
        const std::size_t n = cs->readSome(buf, sizeof buf);
        streamResult.assign(buf, n);
        cs->close();
    }
    std::printf("[smoke] STREAM echo: \"%s\"\n", streamResult.c_str());

    std::string datagramResult = "<none>";
    {
        const std::string ping = "wrapper-datagram-ping";
        client->sendDatagram(server->routingHost(), ping.data(), ping.size());
        std::string peer;
        const auto got = client->receiveDatagram(peer, milliseconds(180000));
        if (!got.empty()) { datagramResult.assign(got.begin(), got.end()); }
    }
    std::printf("[smoke] DATAGRAM echo: \"%s\"\n", datagramResult.c_str());

    const auto transient2 = master.issueTransient(static_cast<std::int64_t>(std::time(nullptr)) + 7200);
    server->refreshOfflineSignature(transient2);
    std::this_thread::sleep_for(seconds(3));
    std::printf("[smoke] REFRESH ready=%d addrStable=%d\n",
        server->ready(), server->routingHost() == bazarish::i2p::routingHost(
            master.publicBase64(), bazarish::i2p::LeaseSetKind::eStandard));

    streamEcho.join();
    datagramEcho.join();
    const bool ok = streamResult == "wrapper-stream-ping" && datagramResult == "wrapper-datagram-ping";
    std::printf("[smoke] RESULT stream=%s datagram=%s refresh=%s\n",
        streamResult == "wrapper-stream-ping" ? "OK" : "FAIL",
        datagramResult == "wrapper-datagram-ping" ? "OK" : "FAIL",
        server->ready() ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
