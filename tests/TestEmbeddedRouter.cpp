// Bazarish project (c) 2026
#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <SSU2.h>
#include <Transports.h>
#include <boost/asio/post.hpp>

#include <chrono>
#include <filesystem>
#include <future>

namespace fs = std::filesystem;

namespace {

constexpr auto kSnapshotPatience = std::chrono::seconds(2);
constexpr auto kTransportBusy = kSnapshotPatience * 2;
constexpr std::size_t kDirSuffixBytes = 8;

}  // namespace

int main()
{
    const fs::path dir = fs::temp_directory_path()
        / ("bazarish-embedded-router-" + bazarish::toHex(bazarish::randomBytes(kDirSuffixBytes)));
    fs::create_directories(dir);
    {
        bazarish::i2p::Router router(bazarish::i2p::offlineRouter(dir));
        CHECK(router.running());
        auto* const ssu2 = ::i2p::transport::transports.GetSSU2Server();
        CHECK(ssu2 != nullptr);

        std::promise<void> release;
        std::shared_future<void> released = release.get_future().share();
        boost::asio::post(ssu2->GetService(), [released]() { released.wait(); });

        const auto asked = std::chrono::steady_clock::now();
        const auto peers = router.transportPeers();
        const auto took = std::chrono::steady_clock::now() - asked;
        CHECK(took < kTransportBusy);
        CHECK(peers.empty());

        release.set_value();
        std::promise<void> drained;
        boost::asio::post(ssu2->GetService(), [&drained]() { drained.set_value(); });
        drained.get_future().wait();
        CHECK(router.transportPeers().empty());

        router.stop();
        CHECK(!router.running());
        CHECK_THROWS(router.createEndpoint(bazarish::i2p::EndpointConfig{}));
    }
    fs::remove_all(dir);
    return 0;
}
