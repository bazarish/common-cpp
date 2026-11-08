// Bazarish project (c) 2026
#include "GatewayAddress.hpp"
#include "I2pRouter.hpp"

#include "TestUtil.hpp"

#include <bazarish/Crypto.hpp>

#include <filesystem>
#include <stdexcept>
#include <string>

using namespace bazarish::client;

int main()
{
    const std::filesystem::path dataDir
        = std::filesystem::temp_directory_path() / "bazarish-transport-choice";
    std::filesystem::remove_all(dataDir);

    CHECK(applyI2pTransport([]() { refuseI2pTransport("the saved gateway is not usable"); }));
    CHECK_THROWS((void)sharedI2pRouter(dataDir));

    const std::string nobodyListening
        = "https://127.0.0.1:1/p#" + bazarish::Identity::generate().fingerprint();
    const GatewayAddress gateway = GatewayAddress::parse(nobodyListening).value();
    CHECK(applyI2pTransport([&gateway]() { setGatewayTransport(gateway); }));
    CHECK_THROWS((void)sharedI2pRouter(dataDir));

    bool set = false;
    CHECK(!applyI2pTransport([&set]() { set = true; }));
    CHECK(!set);

    retireI2pRouter();
    CHECK(!sharedI2pRouterIfRunning().has_value());
    CHECK_THROWS((void)sharedI2pRouter(dataDir));
    CHECK(!applyI2pTransport([]() {}));

    std::filesystem::remove_all(dataDir);
    return 0;
}
