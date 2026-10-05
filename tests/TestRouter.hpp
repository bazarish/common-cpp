// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <filesystem>

namespace bazarish::i2p {

inline RouterConfig offlineRouter(const std::filesystem::path& dataDir)
{
    RouterConfig config;
    config.dataDir = dataDir;
    config.reseedUrls = {(dataDir / "no-reseed.su3").string()};
    return config;
}

}  // namespace bazarish::i2p
