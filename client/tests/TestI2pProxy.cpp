// Bazarish project (c) 2026
#include <bazarish/I2p.hpp>

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

int main()
{
    const fs::path dir = fs::temp_directory_path() / "bazarish-i2p-proxy-test";
    fs::remove_all(dir);
    fs::create_directories(dir);

    bazarish::i2p::setI2pLogging(true);
    bazarish::i2p::RouterConfig config = bazarish::i2p::offlineRouter(dir);
    config.role = bazarish::i2p::Role::eClient;
    std::fprintf(stderr, "proxy: starting the router\n");
    bazarish::i2p::Router router(config);
    std::fprintf(stderr, "proxy: router started\n");

    {
        const bazarish::i2p::ProxyState state = router.proxyState();
        CHECK(state.ntcp2.empty());
        CHECK(state.ssu2.empty());
        CHECK(state.reseed.empty());
        CHECK(state.ssu2Enabled);
    }

    {
        router.setSocksProxy("127.0.0.1", 9050);
        const bazarish::i2p::ProxyState state = router.proxyState();
        CHECK(state.ntcp2 == "socks://127.0.0.1:9050");
        CHECK(state.reseed == "socks://127.0.0.1:9050");
        CHECK(state.ssu2.empty());
        CHECK(!state.ssu2Enabled);
    }
    {
        router.setSocksProxy("proxy.lan", 1080);
        const bazarish::i2p::ProxyState state = router.proxyState();
        CHECK(state.ntcp2 == "socks://proxy.lan:1080");
        CHECK(state.reseed == "socks://proxy.lan:1080");
        CHECK(state.ssu2.empty());
        CHECK(!state.ssu2Enabled);
    }

    {
        router.setSocksProxy(std::string(), 0);
        const bazarish::i2p::ProxyState state = router.proxyState();
        CHECK(state.ntcp2.empty());
        CHECK(state.ssu2.empty());
        CHECK(state.reseed.empty());
        CHECK(state.ssu2Enabled);
    }

    {
        router.setSocksProxy("127.0.0.1", 0);
        const bazarish::i2p::ProxyState state = router.proxyState();
        CHECK(state.ntcp2.empty());
        CHECK(state.ssu2Enabled);
    }

    fs::remove_all(dir);
    std::fprintf(stderr, "TestI2pProxy passed\n");
    return 0;
}
