// Bazarish project (c) 2026
#include "bazarish/ServerDescriptor.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <stdexcept>
#include <string>

using namespace bazarish;

int main()
{
    const std::string fp = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq";

    const std::string i2pA = "http://kkhioqbaxoc5zj6itqgc6pokwtphydax6utj7l6vm5ihklun56lq.b32.i2p/s/9f3c";
    const std::string i2pB = "http://a6i4yj2ovsvrc45gcfdlpqantyjemwdjsuzaqslsvj4le7jphgzq.b32.i2p";

    const ServerDescriptor original{fp, {i2pA, i2pB},
        {"https://relay.example.org:8443/s/9f3c", "https://seed.example.net/"}};
    const std::string uri = encodeServerDescriptor(original);
    CHECK(uri.rfind("bazarish://server?v=1&", 0) == 0);
    CHECK(uri.find("fp=" + fp) != std::string::npos);
    CHECK(uri.find("facade=" + i2pA) != std::string::npos);
    CHECK(uri.find("reseed=https://relay.example.org:8443/s/9f3c") != std::string::npos);

    const ServerDescriptor parsed = parseServerDescriptor(uri);
    CHECK(parsed.fingerprint == fp);
    CHECK(parsed.facades.size() == 2);
    CHECK(parsed.facades[0] == original.facades[0]);
    CHECK(parsed.facades[1] == original.facades[1]);
    CHECK(parsed.reseeds.size() == 2);
    CHECK(parsed.reseeds[0] == original.reseeds[0]);

    CHECK_THROWS(parseServerDescriptor(
        "bazarish://server?v=1&fp=" + fp + "&facade=https://relay.example.org"));
    CHECK_THROWS(parseServerDescriptor("bazarish://server?v=1&fp=" + fp + "&reseed=" + i2pA));
    CHECK_THROWS(parseServerDescriptor(
        "bazarish://server?v=1&fp=" + fp + "&reseed=http://192.168.0.66:8419"));

    const ServerDescriptor noFacades = parseServerDescriptor("bazarish://server?v=1&fp=" + fp);
    CHECK(noFacades.fingerprint == fp);
    CHECK(noFacades.facades.empty());
    CHECK(noFacades.reseeds.empty());

    const ServerDescriptor extra
        = parseServerDescriptor("bazarish://server?v=1&fp=" + fp + "&facade=" + i2pB + "&future=x");
    CHECK(extra.facades.size() == 1);
    CHECK(extra.facades[0] == i2pB);

    CHECK_THROWS(parseServerDescriptor("https://example.com"));
    CHECK_THROWS(parseServerDescriptor("bazarish://invite?v=1&fp=" + fp));
    CHECK_THROWS(parseServerDescriptor("bazarish://server?fp=" + fp));
    CHECK_THROWS(parseServerDescriptor("bazarish://server?v=2&fp=" + fp));
    CHECK_THROWS(parseServerDescriptor("bazarish://server?v=1&fp=tooShort"));
    CHECK_THROWS(parseServerDescriptor("bazarish://server?v=1"));

    std::printf("TestServerDescriptor: all checks passed\n");
    return 0;
}
