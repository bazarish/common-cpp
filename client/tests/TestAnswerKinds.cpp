// Bazarish project (c) 2026
#include "ApiClient.hpp"
#include "FederationFetch.hpp"
#include "GatewayAddress.hpp"
#include "I2pRouter.hpp"
#include "LinkFailure.hpp"

#include "DeviceTestKit.hpp"
#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Portal.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace {

const std::string kRefusal = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
const std::string kNotHttp = "BZ nonsense\r\n\r\n";
const std::string kCutHead = "HTTP/1.1 200 OK\r\nContent-Le";
constexpr int kForbidden = 403;

Bytes bytesOf(const std::string& text)
{
    return Bytes(text.begin(), text.end());
}

std::optional<LinkFailure> failureOf(ApiClient& api)
{
    try {
        (void)api.get("/v1/messaging/storage-usage");
    } catch (const LinkError& error) {
        return error.failure;
    }
    return std::nullopt;
}

std::optional<LinkFailure> failureOf(const std::function<void()>& ask)
{
    try {
        ask();
    } catch (const LinkError& error) {
        return error.failure;
    }
    return std::nullopt;
}

}  // namespace

int main()
try {
    http::Server server(http::Server::Options{});
    test::FakeGateway gateway;
    const int port = gateway.start(server);
    CHECK(port > 0);
    const std::optional<GatewayAddress> gatewayAt = GatewayAddress::parse("http://127.0.0.1:"
        + std::to_string(port) + test::kFakeGatewayPath + "#" + gateway.fingerprint());
    CHECK(gatewayAt.has_value());
    CHECK(applyI2pTransport([&gatewayAt]() { setGatewayTransport(*gatewayAt); }));
    const testutil::ScratchDir scratch("answer-kinds");

    const devicetest::Account account;
    ServerEndpoint endpoint;
    endpoint.serverFingerprint = Identity::generate().fingerprint();
    endpoint.facades = {Facade{test::kFakeGatewayHost, 0}};
    const auto streams = [&gateway]() { return gateway.framesOf(gateway::FrameType::eStreamOpen); };

    {
        gateway.replyToStreams({}, test::FakeGateway::StreamEnd::eReset);
        ApiClient api(account.device, endpoint, scratch.path());
        const std::size_t before = streams();
        CHECK(failureOf(api) == LinkFailure::eServerUnreachable);
        CHECK(api.linkFailure() == LinkFailure::eServerUnreachable);
        CHECK(streams() == before + 1);
        CHECK(failureOf(api) == LinkFailure::eServerUnreachable);
        CHECK(streams() == before + 1);
    }

    {
        gateway.replyToStreams(bytesOf(kCutHead), test::FakeGateway::StreamEnd::eReset);
        ApiClient api(account.device, endpoint, scratch.path());
        CHECK(failureOf(api) == LinkFailure::eServerUnreachable);
        CHECK(api.linkFailure() == LinkFailure::eServerUnreachable);
    }

    {
        gateway.replyToStreams(bytesOf(kNotHttp), test::FakeGateway::StreamEnd::eClose);
        ApiClient api(account.device, endpoint, scratch.path());
        const std::size_t before = streams();
        CHECK(failureOf(api) == LinkFailure::eServerMalformed);
        CHECK(api.linkFailure() == LinkFailure::eServerMalformed);
        CHECK(streams() == before + 1);
        CHECK(failureOf(api) == LinkFailure::eServerMalformed);
        CHECK(streams() == before + 2);
    }

    {
        gateway.replyToStreams(bytesOf(kRefusal), test::FakeGateway::StreamEnd::eClose);
        ApiClient api(account.device, endpoint, scratch.path());
        std::vector<LinkStage> stages;
        api.onLinkStage([&stages](const LinkStage stage) { stages.push_back(stage); });
        CHECK(failureOf(api) == LinkFailure::eServerRefused);
        CHECK(api.linkFailure() == LinkFailure::eServerRefused);
        CHECK(!stages.empty());
        CHECK(stages.front() == LinkStage::eRouter);
        CHECK(stages.back() == LinkStage::eExchange);
        CHECK(std::is_sorted(stages.begin(), stages.end()));
        CHECK(std::count(stages.begin(), stages.end(), LinkStage::eLink) == 1);
        CHECK(std::count(stages.begin(), stages.end(), LinkStage::eDial) == 1);
    }

    i2p::Router& router = readySharedI2pRouter();
    const service::LoginCallback site{test::kFakeGatewayHost, "/login"};
    const std::atomic<bool> cancelled{false};
    const auto fetch = [&]() {
        return getLoginChallengeOverI2p(router, site, i2p::Privacy::eMinimal, "Probe", cancelled);
    };
    const auto post = [&]() {
        return postLoginOverI2p(router, site, "{}", i2p::Privacy::eMinimal, "Probe");
    };

    gateway.replyToStreams({}, test::FakeGateway::StreamEnd::eReset);
    CHECK(!fetch().has_value());
    CHECK(!post().has_value());

    gateway.replyToStreams(bytesOf(kRefusal), test::FakeGateway::StreamEnd::eClose);
    CHECK(failureOf([&]() { (void)fetch(); }) == LinkFailure::eServerRefused);
    CHECK(post() == kForbidden);

    gateway.replyToStreams(bytesOf(kNotHttp), test::FakeGateway::StreamEnd::eClose);
    CHECK(failureOf([&]() { (void)fetch(); }) == LinkFailure::eServerMalformed);
    CHECK(failureOf([&]() { (void)post(); }) == LinkFailure::eServerMalformed);

    retireI2pRouter();
    server.stop();
    std::fprintf(stderr, "TestAnswerKinds passed\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
