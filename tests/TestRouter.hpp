// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <filesystem>

namespace bazarish::i2p {

// A router for a test. The engine bootstraps its netDb while it is being
// constructed, and with no source named it asks the public reseed hosts and keeps
// asking - i2pd waits 30 s between tries and gives up after 180 - so a suite that
// says nothing here has a runtime that belongs to somebody else's web server, and
// reaches third parties every time it runs. Named a file instead, the engine tries
// that and nothing else: one warning in a log that is off by default, and no
// clearnet at all. The file is deliberately absent - a test that meets itself
// inside one gateway needs no netDb.
inline RouterConfig offlineRouter(const std::filesystem::path& dataDir)
{
    RouterConfig config;
    config.dataDir = dataDir;
    config.reseedUrls = {(dataDir / "no-reseed.su3").string()};
    return config;
}

}  // namespace bazarish::i2p
