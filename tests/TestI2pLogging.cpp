// Bazarish project (c) 2026
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <Log.h>

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using bazarish::i2p::I2pLogLevel;
using bazarish::i2p::setI2pLogLevel;

constexpr char kWarnAtNone[] = "warn line at none";
constexpr char kErrorAtNone[] = "error line at none";
constexpr char kDebugAtWarn[] = "debug line at warn";
constexpr char kInfoAtWarn[] = "info line at warn";
constexpr char kWarnAtWarn[] = "warn line at warn";
constexpr char kErrorAtWarn[] = "error line at warn";
constexpr char kDebugAtDebug[] = "debug line at debug";
constexpr char kWarnAtDebug[] = "warn line at debug";
constexpr char kWarnAtError[] = "warn line at error";
constexpr char kErrorAtError[] = "error line at error";
constexpr char kWarnAfterNone[] = "warn line after none";
constexpr char kInfoAtInfo[] = "info line at info";

class Heard {
public:
    void add(const bazarish::log::Level level, const std::string_view message)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        lines_.emplace_back(level, message);
    }

    bool has(const std::string& message) const
    {
        return levelOf(message).has_value();
    }

    std::optional<bazarish::log::Level> levelOf(const std::string& message) const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [level, text] : lines_) {
            if (text == message) {
                return level;
            }
        }
        return std::nullopt;
    }

private:
    mutable std::mutex mutex_;
    std::vector<std::pair<bazarish::log::Level, std::string>> lines_;
};

}  // namespace

int main()
{
    using bazarish::log::Level;

    CHECK(bazarish::i2p::i2pLogLevelFromString("none") == I2pLogLevel::eNone);
    CHECK(bazarish::i2p::i2pLogLevelFromString("debug") == I2pLogLevel::eDebug);
    CHECK(!bazarish::i2p::i2pLogLevelFromString("warning").has_value());
    CHECK(!bazarish::i2p::i2pLogLevelFromString("").has_value());
    CHECK(bazarish::i2p::i2pLogLevelName(I2pLogLevel::eWarn) == "warn");

    bazarish::log::setLevel(Level::eError);
    Heard heard;
    bazarish::log::setTap([&heard](const Level level, const std::string_view,
                              const std::string_view message) { heard.add(level, message); });
    const std::filesystem::path dir = testutil::freshDir("i2p-logging");
    {
        setI2pLogLevel(I2pLogLevel::eNone);
        bazarish::i2p::Router router(bazarish::i2p::offlineRouter(dir));
        CHECK(router.running());
        CHECK(bazarish::i2p::i2pLogLevel() == I2pLogLevel::eNone);

        LogPrint(eLogWarning, kWarnAtNone);
        LogPrint(eLogError, kErrorAtNone);

        setI2pLogLevel(I2pLogLevel::eWarn);
        LogPrint(eLogDebug, kDebugAtWarn);
        LogPrint(eLogInfo, kInfoAtWarn);
        LogPrint(eLogWarning, kWarnAtWarn);
        LogPrint(eLogError, kErrorAtWarn);
        CHECK(testutil::waitFor([&heard]() { return heard.has(kErrorAtWarn); }));
        CHECK(heard.levelOf(kWarnAtWarn) == Level::eWarn);
        CHECK(heard.levelOf(kErrorAtWarn) == Level::eError);

        setI2pLogLevel(I2pLogLevel::eDebug);
        LogPrint(eLogDebug, kDebugAtDebug);
        LogPrint(eLogWarning, kWarnAtDebug);
        CHECK(testutil::waitFor([&heard]() { return heard.has(kWarnAtDebug); }));
        CHECK(heard.levelOf(kDebugAtDebug) == Level::eDebug);

        setI2pLogLevel(I2pLogLevel::eError);
        LogPrint(eLogWarning, kWarnAtError);
        LogPrint(eLogError, kErrorAtError);
        CHECK(testutil::waitFor([&heard]() { return heard.has(kErrorAtError); }));

        setI2pLogLevel(I2pLogLevel::eNone);
        LogPrint(eLogWarning, kWarnAfterNone);
        setI2pLogLevel(I2pLogLevel::eInfo);
        LogPrint(eLogInfo, kInfoAtInfo);
        CHECK(testutil::waitFor([&heard]() { return heard.has(kInfoAtInfo); }));
        CHECK(heard.levelOf(kInfoAtInfo) == Level::eInfo);

        for (const char* const silent :
            {kWarnAtNone, kErrorAtNone, kDebugAtWarn, kInfoAtWarn, kWarnAtError, kWarnAfterNone}) {
            CHECK(!heard.has(silent));
        }

        setI2pLogLevel(I2pLogLevel::eNone);
        router.stop();
    }
    bazarish::log::setTap({});
    std::filesystem::remove_all(dir);
    return 0;
}
