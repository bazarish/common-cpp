// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "FakeGateway.hpp"
#include "TestUtil.hpp"

#include <chrono>
#include <memory>
#include <string>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kReadyWithin{10};
constexpr std::chrono::milliseconds kLostWithin{10000};

i2p::GatewayTarget targetOf(const test::FakeGateway& fake, const int port)
{
    return {"127.0.0.1", port, test::kFakeGatewayPath, fake.fingerprint(), false};
}

}  // namespace

int main()
{
    http::Server first(http::Server::Options{});
    test::FakeGateway was;
    const int firstPort = was.start(first);
    CHECK(firstPort > 0);
    http::Server second(http::Server::Options{});
    test::FakeGateway now;
    const int secondPort = now.start(second);
    CHECK(secondPort > 0);

    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    const i2p::GatewayTarget start = targetOf(was, firstPort);
    config.gatewayHost = start.host;
    config.gatewayPort = start.port;
    config.gatewayPath = start.path;
    config.gatewayFingerprint = start.fingerprint;
    config.gatewayTls = start.tls;
    i2p::Router router(config);
    router.start();
    CHECK(router.waitReady(kReadyWithin));

    i2p::EndpointConfig wanted;
    wanted.published = false;
    const std::shared_ptr<i2p::Endpoint> before = router.createEndpoint(wanted);
    CHECK(before->ready());

    router.repointGateway(targetOf(now, secondPort));
    first.stop();
    CHECK(testutil::waitFor([&before]() { return before->lost(); }, kLostWithin));
    CHECK(router.waitReady(kReadyWithin));
    const std::shared_ptr<i2p::Endpoint> after = router.createEndpoint(wanted);
    CHECK(after->ready());

    i2p::RouterConfig sam;
    sam.backend = i2p::Backend::eSam;
    CHECK_THROWS(i2p::Router(sam).repointGateway(targetOf(now, secondPort)));

    router.stop();
    second.stop();
    return 0;
}
