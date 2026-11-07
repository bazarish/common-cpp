// Bazarish project (c) 2026
#include "GatewayAddress.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

int main()
{
    const std::optional<GatewayAddress> full
        = GatewayAddress::parse("https://gate.example:8443/f3a9c2e1b7d4#a-static-token");
    CHECK(full.has_value());
    CHECK(full->host == "gate.example");
    CHECK(full->port == 8443);
    CHECK(full->path == "/f3a9c2e1b7d4");
    CHECK(full->token == "a-static-token");
    CHECK(full->toString() == "https://gate.example:8443/f3a9c2e1b7d4#a-static-token");

    const std::optional<GatewayAddress> plainPort
        = GatewayAddress::parse("https://gate.example/secret#token");
    CHECK(plainPort.has_value());
    CHECK(plainPort->port == 443);
    CHECK(plainPort->toString() == "https://gate.example/secret#token");

    CHECK(!GatewayAddress::parse("http://127.0.0.1:8431/secret#token").has_value());

    const std::optional<GatewayAddress> deep
        = GatewayAddress::parse("https://gate.example/one/two/three#token");
    CHECK(deep.has_value());
    CHECK(deep->path == "/one/two/three");

    CHECK(!GatewayAddress::parse("").has_value());
    CHECK(!GatewayAddress::parse("gate.example/secret#token").has_value());
    CHECK(!GatewayAddress::parse("ftp://gate.example/secret#token").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example/secret").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example/secret#").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example#token").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example/#token").has_value());
    CHECK(!GatewayAddress::parse("https:///secret#token").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example:http/secret#token").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example:0/secret#token").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example:70000/secret#token").has_value());

    const std::optional<GatewayAddress> awkward
        = GatewayAddress::parse("https://gate.example/p#a-b_c.d~e/f=g");
    CHECK(awkward.has_value());
    CHECK(awkward->token == "a-b_c.d~e/f=g");

    const std::string handed = awkward->link();
    CHECK(handed == "https://bazari.sh/#gateway?v=1&url=https://gate.example/p&token=a-b_c.d~e/f=g");
    const std::optional<GatewayAddress> taken = GatewayAddress::fromLink(handed);
    CHECK(taken.has_value() && taken->toString() == awkward->toString());
    const std::optional<GatewayAddress> scheme = GatewayAddress::fromLink(
        "bazarish://gateway?v=1&url=https://127.0.0.1:8431/secret&token=t");
    CHECK(scheme.has_value() && scheme->port == 8431 && scheme->token == "t");
    CHECK(!GatewayAddress::fromLink("bazarish://gateway?v=1&url=http://127.0.0.1:8431/secret&token=t")
            .has_value());
    CHECK(!GatewayAddress::fromLink("https://gate.example/p#token").has_value());
    CHECK(!GatewayAddress::fromLink("https://bazari.sh/#gateway?v=2&url=https://g.example/p&token=t")
            .has_value());
    CHECK(!GatewayAddress::fromLink("https://bazari.sh/#gateway?v=1&url=https://g.example/p")
            .has_value());
    CHECK(!GatewayAddress::fromLink(
        "https://bazari.sh/#gateway?v=1&url=https://g.example/p#x&token=t").has_value());
    CHECK(!GatewayAddress::fromLink("https://bazari.sh/#invite?v=1&url=https://g.example/p&token=t")
            .has_value());

    std::printf("TestGatewayAddress ok\n");
    return 0;
}
