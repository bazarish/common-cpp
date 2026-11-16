// Bazarish project (c) 2026
#include "Client.hpp"
#include "FederationFetch.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>

#include <chrono>
#include <cstdio>
#include <exception>
#include <functional>
#include <optional>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

namespace {

constexpr std::chrono::seconds kReadyWithin{10};
constexpr const char* kPeer = test::kFakeGatewayHost;
const std::string kCardOp = "card";
const std::string kHalfALine = "{\"ok\":tr";
const std::string kNotALine = "not a reply\n";

i2p::RouterConfig gatewayAt(const int port, const test::FakeGateway& fake)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = test::kFakeGatewayPath;
    config.gatewayFingerprint = fake.fingerprint();
    config.gatewayTls = false;
    return config;
}

Bytes bytesOf(const std::string& text)
{
    return Bytes(text.begin(), text.end());
}

// The failure one fetch ends with, and how many streams it opened for it.
void expectFailure(const std::string& what, const std::function<void(test::FakeGateway&)>& arrange,
    const FetchFailure expected)
{
    http::Server server(http::Server::Options{});
    test::FakeGateway fake;
    const int port = fake.start(server);
    CHECK(port > 0);
    arrange(fake);
    i2p::Router router(gatewayAt(port, fake));
    router.start();
    CHECK(router.waitReady(kReadyWithin));

    std::optional<FetchFailure> failed;
    try {
        static_cast<void>(federationFetchOverI2p(
            router, kPeer, kCardOp, bytesOf("asked"), i2p::Privacy::eMinimal, "Probe"));
    } catch (const FetchFailed& error) {
        failed = error.failure();
        std::printf("%s: %s\n", what.c_str(), error.what());
    } catch (const std::exception& error) {
        std::printf("%s: not a named failure: %s\n", what.c_str(), error.what());
    }
    CHECK(failed.has_value() && *failed == expected);
    const std::size_t opens = fake.framesOf(gateway::FrameType::eStreamOpen);
    std::printf("%s: %zu stream(s) opened\n", what.c_str(), opens);
    CHECK(opens == 1);
    router.stop();
    server.stop();
}

}  // namespace

int main()
{
    expectFailure("no lease set", [](test::FakeGateway& fake) { fake.refuseStreams(); },
        FetchFailure::eLeaseSetNotFound);
    expectFailure("never answered",
        [](test::FakeGateway& fake) {
            fake.replyToStreams({}, test::FakeGateway::StreamEnd::eReset);
        },
        FetchFailure::eNotConnected);
    expectFailure("broke off",
        [](test::FakeGateway& fake) {
            fake.replyToStreams(bytesOf(kHalfALine), test::FakeGateway::StreamEnd::eReset);
        },
        FetchFailure::eBrokeAfterOpen);
    expectFailure("malformed",
        [](test::FakeGateway& fake) {
            fake.replyToStreams(bytesOf(kNotALine), test::FakeGateway::StreamEnd::eClose);
        },
        FetchFailure::eProtocol);
    std::fprintf(stderr, "TestFederationFetch passed\n");
    return 0;
}
