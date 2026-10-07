// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <filesystem>

namespace bazarish::i2p {

inline RouterConfig offlineRouter(const std::filesystem::path& dataDir)
{
    RouterConfig config;
    config.dataDir = dataDir;
    // A missing archive, not an unreachable URL: i2pd tries one archive and gives
    // up, while it retries servers for RESEED_GIVEUP_TIMEOUT inside the start call.
    config.reseedUrls = {(dataDir / "no-reseed.su3").string()};
    return config;
}

}  // namespace bazarish::i2p
