// Bazarish project (c) 2026
#include <bazarish/I2p.hpp>

#include "TestUtil.hpp"

#include <cstdint>
#include <cstdio>

int main()
{
    int told = 0;
    const std::uint64_t before = bazarish::i2p::carryReturns();
    bazarish::i2p::onCarryReturned([&told]() { ++told; });
    bazarish::i2p::networkChanged();
    CHECK(told == 1 && bazarish::i2p::carryReturns() == before + 1);

    bazarish::i2p::onCarryReturned({});
    bazarish::i2p::networkChanged();
    CHECK(told == 1 && bazarish::i2p::carryReturns() == before + 2);

    std::printf("TestCarryReturn: all checks passed\n");
    return 0;
}
