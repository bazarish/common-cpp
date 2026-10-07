// Bazarish project (c) 2026
#include "bazarish/PairLink.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <stdexcept>
#include <string>

using namespace bazarish;

int main()
{
    const std::string b33
        = "kkhioqbaxoc5zj6itqgc6pokwtphydax6utj7l6vm5ihklun56lqabcd.b32.i2p";
    const std::string seedA = "https://seed.example.org:8443/s/9f3c";
    const std::string seedB = "https://other.example/";

    const std::string bare = encodePairLink(PairLink{b33, {}});
    CHECK(bare == "bazarish://pair?v=1&dest=" + b33);
    CHECK(parsePairLink(bare).dest == b33);
    CHECK(parsePairLink(bare).reseeds.empty());

    const std::string two = encodePairLink(PairLink{b33, {seedA, seedB}});
    const PairLink back = parsePairLink(two);
    CHECK(back.dest == b33);
    CHECK(back.reseeds.size() == 2);
    CHECK(back.reseeds[0] == seedA);
    CHECK(back.reseeds[1] == seedB);

    CHECK_THROWS(parsePairLink("bazarish://pair?v=2&dest=" + b33));
    CHECK_THROWS(parsePairLink("bazarish://pair?dest=" + b33));
    CHECK_THROWS(parsePairLink("bazarish://pair?v=1"));
    CHECK_THROWS(parsePairLink("bazarish://pair?v=1&dest=nothost"));
    CHECK_THROWS(parsePairLink("bazarish://pair?v=1&dest=" + b33 + "&reseed=http://seed.example/"));
    CHECK_THROWS(
        parsePairLink("bazarish://pair?v=1&dest=" + b33 + "&reseed=seed.b32.i2p"));
    CHECK_THROWS(parsePairLink("bazarish://invite?v=1&dest=" + b33));
    CHECK_THROWS(parsePairLink("bazarish://pairsv=1&dest=" + b33));
    CHECK_THROWS(parsePairLink("bazarish://pair?v=1&dest=" + b33 + "&broken"));
    CHECK_THROWS(parsePairLink("bazarish://pair?"));

    const PairLink ignored = parsePairLink("bazarish://pair?v=1&dest=" + b33 + "&x=y");
    CHECK(ignored.dest == b33);
    CHECK(ignored.reseeds.empty());

    const PairLink emptySeed = parsePairLink("bazarish://pair?v=1&dest=" + b33 + "&reseed=");
    CHECK(emptySeed.reseeds.empty());

    std::puts("TestPairLink passed");
    return 0;
}
