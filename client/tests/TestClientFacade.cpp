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

void testParse()
{
    {
        const Facade f = parseFacadeUrl("http://example.com");
        CHECK(!f.tls);
        CHECK(f.host == "example.com");
        CHECK(f.port == 80);
        CHECK(f.basePath.empty());
    }
    {
        const Facade f = parseFacadeUrl("https://example.com");
        CHECK(f.tls);
        CHECK(f.port == 443);
    }
    {
        const Facade f = parseFacadeUrl("http://127.0.0.1:18482");
        CHECK(!f.tls);
        CHECK(f.host == "127.0.0.1");
        CHECK(f.port == 18482);
        CHECK(f.basePath.empty());
    }
    {
        const Facade f = parseFacadeUrl("https://relay.example.org:8443/s/9f3c");
        CHECK(f.tls);
        CHECK(f.host == "relay.example.org");
        CHECK(f.port == 8443);
        CHECK(f.basePath == "/s/9f3c");
    }
    {
        const Facade f = parseFacadeUrl("http://h:1/path/");
        CHECK(f.basePath == "/path");
    }
    {
        const Facade f = parseFacadeUrl("127.0.0.1:18482");
        CHECK(!f.tls);
        CHECK(f.port == 18482);
    }
}

void testFormatRoundTrip()
{
    const char* urls[] = {
        "http://example.com",
        "https://example.com",
        "http://127.0.0.1:18482",
        "https://relay.example.org:8443/s/9f3c",
        "https://host/path",
    };
    for (const char* url : urls) {
        const Facade f = parseFacadeUrl(url);
        const Facade again = parseFacadeUrl(facadeToUrl(f));
        CHECK(again.tls == f.tls);
        CHECK(again.host == f.host);
        CHECK(again.port == f.port);
        CHECK(again.basePath == f.basePath);
    }
    CHECK(facadeToUrl(parseFacadeUrl("https://example.com:443")) == "https://example.com");
    CHECK(facadeToUrl(parseFacadeUrl("http://h:18482")) == "http://h:18482");
}

void testInvalid()
{
    const char* bad[] = {"http://", "ftp://host", "http://host:notaport", "https://:443"};
    for (const char* url : bad) {
        bool threw = false;
        try {
            parseFacadeUrl(url);
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
    }
}

void testEndpointFacades()
{
    ServerEndpoint endpoint;
    endpoint.serverFingerprint = "srvfp";
    endpoint.facades = {parseFacadeUrl("http://a:1"), parseFacadeUrl("https://b:2/x")};
    CHECK(endpoint.facades.size() == 2);
    CHECK(!endpoint.facades[0].tls);
    CHECK(endpoint.facades[0].host == "a");
    CHECK(endpoint.facades[1].tls);
    CHECK(endpoint.facades[1].basePath == "/x");
    CHECK(facadeToUrl(endpoint.facades[1]) == "https://b:2/x");
}

void testServerLink()
{
    ServerLink link;
    link.serverFingerprint = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq";
    link.facadeUrls = {"https://relay.example.org:8443/s/9f3c", "http://127.0.0.1:18482"};
    const std::string uri = encodeServerLink(link);
    CHECK(uri.rfind("bazarish://server?v=1&", 0) == 0);
    CHECK(uri.find("fp=" + link.serverFingerprint) != std::string::npos);
    CHECK(uri.find("facade=https://relay.example.org:8443/s/9f3c") != std::string::npos);
    CHECK(uri.find("facade=http://127.0.0.1:18482") != std::string::npos);

    const ServerLink back = decodeServerLink(uri);
    CHECK(back.serverFingerprint == link.serverFingerprint);
    CHECK(back.facadeUrls.size() == 2);
    CHECK(back.facadeUrls[0] == link.facadeUrls[0]);
    CHECK(back.facadeUrls[1] == link.facadeUrls[1]);

    bool threw = false;
    try {
        decodeServerLink("bazarish://invite/abc");
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
}

void testI2pOnly()
{
    const bazarish::Identity id = bazarish::Identity::generate();
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(false);

    {
        ServerEndpoint endpoint;
        endpoint.serverFingerprint = "srvfp";
        endpoint.facades
            = {parseFacadeUrl("https://clear.example:8443"), parseFacadeUrl("http://abc.b32.i2p")};
        ApiClient api(id, "cid", endpoint, "/tmp/bazarish-test/i2p");
        CHECK(api.activeFacadeUrl() == "http://abc.b32.i2p");
    }
    {
        bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
        ServerEndpoint endpoint;
        endpoint.serverFingerprint = "srvfp";
        endpoint.facades
            = {parseFacadeUrl("https://clear.example:8443"), parseFacadeUrl("http://abc.b32.i2p")};
        ApiClient api(id, "cid", endpoint, "/tmp/bazarish-test/i2p");
        CHECK(api.activeFacadeUrl() == "https://clear.example:8443");
    }
}

}  // namespace

int main()
{
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    testParse();
    testFormatRoundTrip();
    testInvalid();
    testEndpointFacades();
    testServerLink();
    testI2pOnly();
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    std::fprintf(stderr, "TestFacade passed\n");
    return 0;
}
