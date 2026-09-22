// Bazarish project (c) 2026
#include "GatewayAddress.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::client;

int main()
{
    // The whole of what an operator hands out, in one string.
    const std::optional<GatewayAddress> full
        = GatewayAddress::parse("https://gate.example:8443/f3a9c2e1b7d4#a-static-token");
    CHECK(full.has_value());
    CHECK(full->host == "gate.example");
    CHECK(full->port == 8443);
    CHECK(full->path == "/f3a9c2e1b7d4");
    CHECK(full->token == "a-static-token");
    CHECK(full->tls);
    // It comes back the way it went in, so a settings page can show what it has.
    CHECK(full->toString() == "https://gate.example:8443/f3a9c2e1b7d4#a-static-token");

    // Without a port it is the one https uses, and the text says so by leaving
    // it out again.
    const std::optional<GatewayAddress> plainPort
        = GatewayAddress::parse("https://gate.example/secret#token");
    CHECK(plainPort.has_value());
    CHECK(plainPort->port == 443);
    CHECK(plainPort->toString() == "https://gate.example/secret#token");

    // http is the hop to a front on this same machine, and says so.
    const std::optional<GatewayAddress> local
        = GatewayAddress::parse("http://127.0.0.1:8431/secret#token");
    CHECK(local.has_value());
    CHECK(!local->tls);
    CHECK(local->port == 8431);

    // A path deeper than one segment is a path like any other.
    const std::optional<GatewayAddress> deep
        = GatewayAddress::parse("https://gate.example/one/two/three#token");
    CHECK(deep.has_value());
    CHECK(deep->path == "/one/two/three");

    // What is not one of these is said to be not one of these, rather than
    // turned into something that will fail later and elsewhere.
    CHECK(!GatewayAddress::parse("").has_value());
    CHECK(!GatewayAddress::parse("gate.example/secret#token").has_value());
    CHECK(!GatewayAddress::parse("ftp://gate.example/secret#token").has_value());
    // No token.
    CHECK(!GatewayAddress::parse("https://gate.example/secret").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example/secret#").has_value());
    // No path, or a path that is only the slash: there is no secret in either.
    CHECK(!GatewayAddress::parse("https://gate.example#token").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example/#token").has_value());
    // No host.
    CHECK(!GatewayAddress::parse("https:///secret#token").has_value());
    // A port that is not a number, or not a port.
    CHECK(!GatewayAddress::parse("https://gate.example:http/secret#token").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example:0/secret#token").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example:70000/secret#token").has_value());

    // A token with the characters a random string has keeps all of them.
    const std::optional<GatewayAddress> awkward
        = GatewayAddress::parse("https://gate.example/p#a-b_c.d~e/f=g");
    CHECK(awkward.has_value());
    CHECK(awkward->token == "a-b_c.d~e/f=g");

    std::printf("TestGatewayAddress ok\n");
    return 0;
}
