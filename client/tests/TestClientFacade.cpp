// Bazarish project (c) 2026
#include "ApiClient.hpp"
#include <bazarish/ServerDescriptor.hpp>
#include "Invite.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace bazarish::client;

namespace {

const std::string kI2pHost = "abc.b32.i2p";

void testParse()
{
    {
        const Facade f = parseFacadeAddress(kI2pHost);
        CHECK(f.host == kI2pHost);
        CHECK(f.port == 0);
    }
    {
        const Facade f = parseFacadeAddress("127.0.0.1:18482");
        CHECK(f.host == "127.0.0.1");
        CHECK(f.port == 18482);
    }
}

void testFormatRoundTrip()
{
    for (const char* address : {"abc.b32.i2p", "127.0.0.1:18482", "h:1"}) {
        CHECK(facadeAddress(parseFacadeAddress(address)) == address);
    }
}

void testInvalid()
{
    const char* bad[] = {"", "http://abc.b32.i2p", "abc.b32.i2p/s/9f3c", "abc.b32.i2p/",
        "host:notaport", ":443", "host:0", "host:70000"};
    for (const char* address : bad) {
        CHECK_THROWS(parseFacadeAddress(address));
    }
}

void testServerLink()
{
    ServerLink link;
    link.serverFingerprint = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq";
    link.facades = {kI2pHost, "127.0.0.1:18482"};
    const std::string uri = encodeServerLink(link);
    CHECK(uri.rfind("bazarish://server?v=1&", 0) == 0);
    CHECK(uri.find("fp=" + link.serverFingerprint) != std::string::npos);
    CHECK(uri.find("facade=" + kI2pHost) != std::string::npos);
    CHECK(uri.find("facade=127.0.0.1:18482") != std::string::npos);

    const ServerLink back = decodeServerLink(uri);
    CHECK(back.serverFingerprint == link.serverFingerprint);
    CHECK(back.facades == link.facades);

    CHECK_THROWS(decodeServerLink("bazarish://invite/abc"));
}

void testI2pOnly()
{
    const bazarish::Identity id = bazarish::Identity::generate();
    const std::vector<Facade> facades
        = {parseFacadeAddress("clear.example:8443"), parseFacadeAddress(kI2pHost)};
    {
        bazarish::setAllowFacadeWithoutI2pForDevPurposes(false);
        ApiClient api(id, "cid", ServerEndpoint{"srvfp", facades, {}}, "/tmp/bazarish-test/i2p");
        CHECK(api.activeFacadeAddress() == kI2pHost);
    }
    {
        bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
        ApiClient api(id, "cid", ServerEndpoint{"srvfp", facades, {}}, "/tmp/bazarish-test/i2p");
        CHECK(api.activeFacadeAddress() == "clear.example:8443");
    }
}

}  // namespace

int main()
{
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    testParse();
    testFormatRoundTrip();
    testInvalid();
    testServerLink();
    testI2pOnly();
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    std::fprintf(stderr, "TestFacade passed\n");
    return 0;
}
