// Bazarish project (c) 2026
#include <bazarish/I2p.hpp>

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

int main()
{
    const fs::path dir = fs::temp_directory_path() / "bazarish-i2p-reseed-test";
    fs::remove_all(dir);
    fs::create_directories(dir);
    const std::string archive = (dir / "no-reseed.su3").string();

    {
        bazarish::i2p::RouterConfig refused = bazarish::i2p::offlineRouter(dir);
        refused.reseedUrls.push_back((dir / "second-no-reseed.su3").string());
        CHECK_THROWS(bazarish::i2p::Router(refused));
    }

    bazarish::i2p::RouterConfig config = bazarish::i2p::offlineRouter(dir);
    config.role = bazarish::i2p::Role::eClient;
    bazarish::i2p::Router router(config);
    CHECK(router.running());
    CHECK(router.capabilities().reseed);

    {
        const bazarish::i2p::ReseedState state = router.reseedState();
        CHECK(state.file == archive);
        CHECK(!state.urls.empty());
    }
    const std::string builtIn = router.reseedState().urls;

    router.setReseedUrls({"https://seed.example.org"});
    {
        const bazarish::i2p::ReseedState state = router.reseedState();
        CHECK(state.urls == "https://seed.example.org/");
        CHECK(state.file.empty());
    }

    router.setReseedUrls({"https://one.example/", "https://two.example"});
    CHECK(router.reseedState().urls == "https://one.example/,https://two.example/");

    router.setReseedUrls({});
    {
        const bazarish::i2p::ReseedState state = router.reseedState();
        CHECK(state.urls == builtIn);
        CHECK(state.file.empty());
    }

    router.setReseedUrls({archive});
    {
        const bazarish::i2p::ReseedState state = router.reseedState();
        CHECK(state.file == archive);
        CHECK(state.urls == builtIn);
    }

    CHECK_THROWS(router.setReseedUrls({archive, (dir / "other.su3").string()}));

    fs::remove_all(dir);
    std::puts("TestI2pReseed passed");
    return 0;
}
