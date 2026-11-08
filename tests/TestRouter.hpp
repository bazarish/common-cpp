// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <filesystem>

namespace bazarish::i2p {

inline RouterConfig offlineRouter(const std::filesystem::path& dataDir)
{
    RouterConfig config;
    config.dataDir = dataDir;
    // i2pd gives up on a missing archive at once but retries servers for RESEED_GIVEUP_TIMEOUT.
    config.reseedFile = dataDir / "no-reseed.su3";
    return config;
}

}  // namespace bazarish::i2p
