// Bazarish project (c) 2026
// Two destinations on one external router, exchanging several streams: what a
// daemon's federation does, with nothing else in the way.
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;

int main(int argc, char** argv)
{
    log::setComponent("samstreams");
    log::setLevel(log::Level::eInfo);
    const int rounds = argc > 1 ? std::stoi(argv[1]) : 3;
    const std::size_t payload = argc > 2 ? static_cast<std::size_t>(std::stoul(argv[2])) : 32;

    i2p::RouterConfig config;
    config.backend = i2p::Backend::eSam;
    config.samHost = "127.0.0.1";
    config.samControlPort = 7656;
    i2p::Router router(config);

    const auto make = [&router](const char* label) {
        const i2p::EndpointConfig endpoint{
            router.generateKeys(), i2p::Privacy::eMinimal, 3, true, label, {}};
        return router.createEndpoint(endpoint);
    };
    const auto server = make("server");
    const auto client = make("client");
    std::printf("server %s\nclient %s\n", server->routingHost().c_str(),
        client->routingHost().c_str());
    if (!server->waitReady(std::chrono::seconds(180))
        || !client->waitReady(std::chrono::seconds(180))) {
        std::printf("FAIL: destinations did not come up\n");
        return 1;
    }

    std::atomic<int> served{0};
    std::thread accepting([&]() {
        for (int i = 0; i < rounds; ++i) {
            try {
                std::string caller;
                const auto stream = server->accept(caller, std::chrono::seconds(120));
                if (!stream) {
                    std::printf("FAIL: no stream accepted on round %d\n", i);
                    return;
                }
                std::vector<unsigned char> in(payload);
                stream->readExact(in.data(), in.size());
                stream->writeAll(in.data(), in.size());  // echo
                stream->close();
                ++served;
            } catch (const std::exception& error) {
                std::printf("FAIL: accept round %d: %s\n", i, error.what());
                return;
            }
        }
    });

    int ok = 0;
    for (int i = 0; i < rounds; ++i) {
        try {
            const auto stream = client->connect(server->routingHost(), std::chrono::seconds(120));
            std::vector<unsigned char> out(payload, static_cast<unsigned char>('a' + i));
            stream->writeAll(out.data(), out.size());
            std::vector<unsigned char> back(payload);
            stream->readExact(back.data(), back.size());
            stream->close();
            if (back == out) {
                ++ok;
                std::printf("round %d: %zu bytes round-tripped\n", i, payload);
            } else {
                std::printf("FAIL round %d: the echo differs\n", i);
            }
        } catch (const std::exception& error) {
            std::printf("FAIL round %d: %s\n", i, error.what());
        }
    }
    accepting.join();
    std::printf("%d/%d round trips, %d served\n", ok, rounds, served.load());
    return ok == rounds ? 0 : 1;
}
