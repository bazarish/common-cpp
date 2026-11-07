// Bazarish project (c) 2026
#include "GatewayAddress.hpp"
#include "I2pRouter.hpp"

#include "TestUtil.hpp"

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

    constexpr const char* kNobodyListening = "https://127.0.0.1:1/p#t";
    const GatewayAddress gateway = GatewayAddress::parse(kNobodyListening).value();
    CHECK(applyI2pTransport([&gateway]() { setGatewayTransport(gateway, "pin"); }));
    CHECK_THROWS((void)sharedI2pRouter(dataDir));

    bool set = false;
    CHECK(!applyI2pTransport([&set]() { set = true; }));
    CHECK(!set);

    retireI2pRouter();
    CHECK(sharedI2pRouterIfRunning() == nullptr);
    CHECK_THROWS((void)sharedI2pRouter(dataDir));
    CHECK(!applyI2pTransport([]() {}));

    std::filesystem::remove_all(dataDir);
    return 0;
}
