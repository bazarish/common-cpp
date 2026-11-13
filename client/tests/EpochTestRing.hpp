// Bazarish project (c) 2026
#pragma once

#include "EpochRing.hpp"

#include <bazarish/Epochs.hpp>

#include <memory>
#include <string>

namespace bazarish::client::epochtest {

// Keys for the epoch around `utcSeconds` and the ones on either side of it.
inline std::shared_ptr<EpochRing> ringAround(const std::int64_t utcSeconds, const std::string& by)
{
    const std::shared_ptr<EpochRing> ring = std::make_shared<EpochRing>();
    const EpochNumber current = epochAt(utcSeconds);
    for (EpochNumber n = current - 1; n <= current + 1; ++n) {
        ring->add(n, kFirstEpochGeneration, by, Key::generateSealing());
    }
    return ring;
}

}  // namespace bazarish::client::epochtest
