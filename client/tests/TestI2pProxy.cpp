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

    // One router per process, so the cases below move the same one between
    // settings - which is what the application does when the user saves.
    bazarish::i2p::RouterConfig config = bazarish::i2p::offlineRouter(dir);
    config.role = bazarish::i2p::Role::eClient;
    bazarish::i2p::Router router(config);

    // No proxy: every transport goes straight out, and the datagram one is on.
    {
        const bazarish::i2p::ProxyState state = router.proxyState();
        CHECK(state.ntcp2.empty());
        CHECK(state.ssu2.empty());
        CHECK(state.reseed.empty());
        CHECK(state.ssu2Enabled);
    }

    // With a proxy set, the router connections and the reseed go through it and
    // the datagram transport is off - always, whether the proxy is named by
    // address or by host, because SSU2 is what would otherwise leave around it.
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

    // Cleared: back to straight out, with the datagram transport on again.
    {
        router.setSocksProxy(std::string(), 0);
        const bazarish::i2p::ProxyState state = router.proxyState();
        CHECK(state.ntcp2.empty());
        CHECK(state.ssu2.empty());
        CHECK(state.reseed.empty());
        CHECK(state.ssu2Enabled);
    }

    // A port of zero is not a proxy either.
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
