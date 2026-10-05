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
    CHECK(full->tls);
    CHECK(full->toString() == "https://gate.example:8443/f3a9c2e1b7d4#a-static-token");

    const std::optional<GatewayAddress> plainPort
        = GatewayAddress::parse("https://gate.example/secret#token");
    CHECK(plainPort.has_value());
    CHECK(plainPort->port == 443);
    CHECK(plainPort->toString() == "https://gate.example/secret#token");

    const std::optional<GatewayAddress> local
        = GatewayAddress::parse("http://127.0.0.1:8431/secret#token");
    CHECK(local.has_value());
    CHECK(!local->tls);
    CHECK(local->port == 8431);

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

    std::printf("TestGatewayAddress ok\n");
    return 0;
}
