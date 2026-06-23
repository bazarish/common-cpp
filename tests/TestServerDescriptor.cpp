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

    // Round-trips fingerprint plus every facade URL, in order.
    const ServerDescriptor original{
        fp, {"https://relay.example.org:8443/s/9f3c", "http://192.168.0.66:8419"}};
    const std::string uri = encodeServerDescriptor(original);
    CHECK(uri.rfind("bazarish://server?v=1&", 0) == 0);
    // The payload is legible: the fingerprint and facade URLs appear verbatim.
    CHECK(uri.find("fp=" + fp) != std::string::npos);
    CHECK(uri.find("facade=https://relay.example.org:8443/s/9f3c") != std::string::npos);
    CHECK(uri.find("facade=http://192.168.0.66:8419") != std::string::npos);

    const ServerDescriptor parsed = parseServerDescriptor(uri);
    CHECK(parsed.fingerprint == fp);
    CHECK(parsed.facades.size() == 2);
    CHECK(parsed.facades[0] == original.facades[0]);
    CHECK(parsed.facades[1] == original.facades[1]);

    // A descriptor with no facades is still valid (the fingerprint stands alone).
    const ServerDescriptor noFacades = parseServerDescriptor("bazarish://server?v=1&fp=" + fp);
    CHECK(noFacades.fingerprint == fp);
    CHECK(noFacades.facades.empty());

    // Unknown keys are ignored for forward compatibility.
    const ServerDescriptor extra
        = parseServerDescriptor("bazarish://server?v=1&fp=" + fp + "&facade=http://h:1&future=x");
    CHECK(extra.facades.size() == 1);
    CHECK(extra.facades[0] == "http://h:1");

    CHECK_THROWS(parseServerDescriptor("https://example.com"));                  // wrong scheme
    CHECK_THROWS(parseServerDescriptor("bazarish://invite?v=1&fp=" + fp));       // wrong artifact
    CHECK_THROWS(parseServerDescriptor("bazarish://server?fp=" + fp));           // missing version
    CHECK_THROWS(parseServerDescriptor("bazarish://server?v=2&fp=" + fp));       // bad version
    CHECK_THROWS(parseServerDescriptor("bazarish://server?v=1&fp=tooShort"));    // bad fingerprint
    CHECK_THROWS(parseServerDescriptor("bazarish://server?v=1"));                // missing fingerprint

    std::printf("TestServerDescriptor: all checks passed\n");
    return 0;
}
