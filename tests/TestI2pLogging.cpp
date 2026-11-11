// Bazarish project (c) 2026
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <Log.h>

#include <algorithm>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr char kWhileOff[] = "i2pd line while its log is off";
constexpr char kAfterOn[] = "i2pd line after its log is switched on";
constexpr char kAfterOff[] = "i2pd line after its log is switched off";
constexpr char kOnAgain[] = "i2pd line after its log is on again";

class Heard {
public:
    void add(const std::string_view message)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        lines_.emplace_back(message);
    }

    bool has(const std::string& message) const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return std::find(lines_.begin(), lines_.end(), message) != lines_.end();
    }

private:
    mutable std::mutex mutex_;
    std::vector<std::string> lines_;
};

}  // namespace

int main()
{
    bazarish::log::setLevel(bazarish::log::Level::eError);
    Heard heard;
    bazarish::log::setTap([&heard](const bazarish::log::Level, const std::string_view,
                              const std::string_view message) { heard.add(message); });
    const std::filesystem::path dir = testutil::freshDir("i2p-logging");
    {
        bazarish::i2p::setI2pLogging(false);
        bazarish::i2p::Router router(bazarish::i2p::offlineRouter(dir));
        CHECK(router.running());

        LogPrint(eLogWarning, kWhileOff);
        bazarish::i2p::setI2pLogging(true);
        LogPrint(eLogWarning, kAfterOn);
        CHECK(testutil::waitFor([&heard]() { return heard.has(kAfterOn); }));
        CHECK(!heard.has(kWhileOff));

        bazarish::i2p::setI2pLogging(false);
        LogPrint(eLogWarning, kAfterOff);
        bazarish::i2p::setI2pLogging(true);
        LogPrint(eLogWarning, kOnAgain);
        CHECK(testutil::waitFor([&heard]() { return heard.has(kOnAgain); }));
        CHECK(!heard.has(kAfterOff));

        router.stop();
    }
    bazarish::log::setTap({});
    std::filesystem::remove_all(dir);
    return 0;
}
