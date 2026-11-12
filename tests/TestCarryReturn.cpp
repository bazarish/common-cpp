// Bazarish project (c) 2026
#include <bazarish/I2p.hpp>

#include "TestUtil.hpp"

#include <cstdint>
#include <cstdio>
#include <memory>

int main()
{
    int first = 0;
    int second = 0;
    const std::uint64_t before = bazarish::i2p::carryReturns();
    auto firstWatch = std::make_unique<bazarish::i2p::CarryWatch>([&first]() { ++first; });
    {
        const bazarish::i2p::CarryWatch secondWatch([&second]() { ++second; });
        bazarish::i2p::networkChanged();
        CHECK(first == 1 && second == 1 && bazarish::i2p::carryReturns() == before + 1);
    }
    bazarish::i2p::networkChanged();
    CHECK(first == 2 && second == 1 && bazarish::i2p::carryReturns() == before + 2);

    firstWatch.reset();
    bazarish::i2p::networkChanged();
    CHECK(first == 2 && second == 1 && bazarish::i2p::carryReturns() == before + 3);

    std::printf("TestCarryReturn: all checks passed\n");
    return 0;
}
