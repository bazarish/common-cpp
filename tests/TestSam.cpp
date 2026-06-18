// Bazarish project (c) 2026
#include "bazarish/Sam.hpp"

#include "TestUtil.hpp"

#include <cstdio>

using namespace bazarish;

// Integration test against a local i2pd SAM API. The environment is
// expected to provide it; an unreachable SAM bridge is a test failure.
int main()
{
    SamClient sam(SamClient::kDefaultHost, SamClient::kDefaultPort);
    std::printf("SAM version: %s\n", sam.version().c_str());
    CHECK(!sam.version().empty());

    const SamClient::Destination destination = sam.generateDestination();
    CHECK(!destination.pub.empty());
    CHECK(!destination.priv.empty());
    // The private blob embeds the public destination.
    CHECK(destination.priv.size() > destination.pub.size());

    // Destinations are unique per generation.
    const SamClient::Destination another = sam.generateDestination();
    CHECK(another.pub != destination.pub);

    // Privacy profiles map to the documented SESSION CREATE tunnel options.
    CHECK(i2pPrivacyOptions(I2pPrivacy::eMinimal) == "inbound.length=1 outbound.length=1");
    CHECK(i2pPrivacyOptions(I2pPrivacy::eMiddle)
        == "inbound.length=1 outbound.length=1 inbound.lengthVariance=1 outbound.lengthVariance=1");
    CHECK(i2pPrivacyOptions(I2pPrivacy::eMax)
        == "inbound.length=2 outbound.length=2 inbound.lengthVariance=1 outbound.lengthVariance=1");
    CHECK(i2pPrivacyFromString("minimal") == I2pPrivacy::eMinimal);
    CHECK(i2pPrivacyFromString("middle") == I2pPrivacy::eMiddle);
    CHECK(i2pPrivacyFromString("max") == I2pPrivacy::eMax);
    CHECK(!i2pPrivacyFromString("bogus").has_value());

    // Tunnel-quantity options (load balancing across tunnels for one address);
    // the value is clamped to [1, 16].
    CHECK(i2pTunnelQuantityOptions(3) == "inbound.quantity=3 outbound.quantity=3");
    CHECK(i2pTunnelQuantityOptions(16) == "inbound.quantity=16 outbound.quantity=16");
    CHECK(i2pTunnelQuantityOptions(99) == "inbound.quantity=16 outbound.quantity=16");
    CHECK(i2pTunnelQuantityOptions(0) == "inbound.quantity=1 outbound.quantity=1");

    return 0;
}
