// Bazarish project (c) 2026
#include <bazarish/I2p.hpp>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <exception>
#include <string>
#include <thread>

using namespace std::chrono;

constexpr int kQuietHoldSeconds = 30;
constexpr int kReadDeadlineSeconds = 3;
constexpr int kDeadlineSlackSeconds = 10;

constexpr int kDelegationDays = 2;

int main(int argc, char** argv)
{
    const std::string dataDir = argc > 1 ? argv[1] : "/tmp/baz-i2p-smoke";

    bazarish::i2p::RouterConfig config;
    config.dataDir = dataDir;
    config.role = bazarish::i2p::Role::eClient;
    bazarish::i2p::Router router(config);
    std::printf("[smoke] waiting for router...\n");
    router.waitReady(seconds(300));
    std::printf("[smoke] router ready=%d knownRouters=%d\n", router.ready(), router.knownRouters());

    const auto master = bazarish::i2p::Keys::generate();
    const auto transient = master.issueTransient(kDelegationDays);
    bazarish::i2p::EndpointConfig serverCfg{transient, bazarish::i2p::Privacy::eMax, 3, true};
    bazarish::i2p::EndpointConfig clientCfg{
        bazarish::i2p::Keys::generate(), bazarish::i2p::Privacy::eMax, 3, true};
    auto server = router.createEndpoint(serverCfg);
    auto client = router.createEndpoint(clientCfg);
    std::printf("[smoke] server addr=%s offline=%d b33days=%d sameAddr=%d\n",
        server->routingHost().c_str(), transient.isOffline(), transient.b33OfflineKeyDays(),
        server->routingHost() == bazarish::i2p::routingHost(master.publicBase64()));

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

    std::thread quietPeer([&] {
        std::string peer;
        auto s = server->accept(peer, seconds(300));
        if (!s) { return; }
        std::this_thread::sleep_for(seconds(kQuietHoldSeconds));
        s->close();
    });
    std::string deadlineResult = "<none>";
    if (auto cs = client->connect(server->routingHost(), seconds(240)))
    {
        cs->setReadTimeout(seconds(kReadDeadlineSeconds));
        const std::string ping = "wrapper-quiet-ping";
        cs->writeAll(ping.data(), ping.size());
        const auto started = steady_clock::now();
        char buf[256];
        try {
            const std::size_t n = cs->readSome(buf, sizeof buf);
            deadlineResult = "read returned " + std::to_string(n) + " bytes";
        } catch (const std::exception& error) {
            const auto waited = duration_cast<seconds>(steady_clock::now() - started).count();
            std::printf("[smoke] read gave up after %llds: %s\n",
                static_cast<long long>(waited), error.what());
            deadlineResult = waited <= kReadDeadlineSeconds + kDeadlineSlackSeconds
                ? "timed out"
                : "timed out late";
        }
        cs->close();
    }
    std::printf("[smoke] READ DEADLINE: %s\n", deadlineResult.c_str());

    std::string datagramResult = "<none>";
    {
        const std::string ping = "wrapper-datagram-ping";
        client->sendDatagram(server->routingHost(), ping.data(), ping.size());
        std::string peer;
        const auto got = client->receiveDatagram(peer, milliseconds(180000));
        if (!got.empty()) { datagramResult.assign(got.begin(), got.end()); }
    }
    std::printf("[smoke] DATAGRAM echo: \"%s\"\n", datagramResult.c_str());

    const auto transient2 = master.issueTransient(kDelegationDays + 1);
    server->refreshOfflineSignature(transient2);
    std::this_thread::sleep_for(seconds(3));
    std::printf("[smoke] REFRESH ready=%d addrStable=%d\n", server->ready(),
        server->routingHost() == bazarish::i2p::routingHost(master.publicBase64()));

    streamEcho.join();
    datagramEcho.join();
    quietPeer.join();
    const bool ok = streamResult == "wrapper-stream-ping"
        && datagramResult == "wrapper-datagram-ping" && deadlineResult == "timed out";
    std::printf("[smoke] RESULT stream=%s datagram=%s refresh=%s deadline=%s\n",
        streamResult == "wrapper-stream-ping" ? "OK" : "FAIL",
        datagramResult == "wrapper-datagram-ping" ? "OK" : "FAIL",
        server->ready() ? "OK" : "FAIL",
        deadlineResult == "timed out" ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
