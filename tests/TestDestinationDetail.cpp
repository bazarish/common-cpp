// Bazarish project (c) 2026
#include <bazarish/I2p.hpp>

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace fs = std::filesystem;

namespace {

constexpr std::size_t kHopHashChars = 6;
const std::string kB32Suffix = ".b32.i2p";
const std::string kLabel = "Detail probe";
const std::string kAccountLabel = "Probe account";

bool knownState(const bazarish::i2p::TunnelState state)
{
    using bazarish::i2p::TunnelState;
    return state == TunnelState::eBuilding || state == TunnelState::eEstablished
        || state == TunnelState::eExpiring || state == TunnelState::eFailed;
}

}  // namespace

int main()
{
    namespace i2p = bazarish::i2p;
    const fs::path dir = testutil::freshDir("destination-detail");
    {
        i2p::Router router(i2p::offlineRouter(dir));
        CHECK(router.capabilities().destinationDetail);

        i2p::EndpointConfig config;
        config.label = kLabel;
        config.accountLabel = kAccountLabel;
        const std::shared_ptr<i2p::Endpoint> endpoint = router.createEndpoint(config);
        const std::string host = endpoint->routingHost();
        const std::string stranger = i2p::routingHost(i2p::Keys::generate().publicBase64());

        const std::optional<i2p::DestinationDetail> detail = router.destinationDetail(host);
        CHECK(detail.has_value());
        CHECK(detail->destination.label == kLabel);
        CHECK(detail->destination.accountLabel == kAccountLabel);
        CHECK(detail->destination.host == host);
        CHECK(!detail->destination.closing);
        for (const i2p::TunnelDetail& tunnel : detail->tunnels) {
            CHECK(knownState(tunnel.state));
            CHECK(!tunnel.latencyMs.has_value() || *tunnel.latencyMs >= 0);
            for (const std::string& hop : tunnel.hops) {
                CHECK(hop.size() == kHopHashChars);
            }
        }
        for (const i2p::RemoteLeaseSet& leaseSet : detail->leaseSets) {
            CHECK(leaseSet.host.ends_with(kB32Suffix));
            CHECK(leaseSet.leases >= 0);
        }

        CHECK(!router.destinationDetail(stranger).has_value());
        CHECK(!router.refreshLeaseSet(host, stranger));
        CHECK(!router.refreshLeaseSet(stranger, host));
    }
    fs::remove_all(dir);
    return 0;
}
