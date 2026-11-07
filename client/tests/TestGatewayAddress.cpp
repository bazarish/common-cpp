// Bazarish project (c) 2026
#include "GatewayAddress.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

namespace {

const std::string kFingerprint(52, 'a');

std::optional<GatewayAddress> parsed(const std::string& base)
{
    return GatewayAddress::parse(base + "#" + kFingerprint);
}

}  // namespace

int main()
{
    const std::optional<GatewayAddress> full = parsed("https://gate.example:8443/f3a9c2e1b7d4");
    CHECK(full.has_value());
    CHECK(full->host == "gate.example");
    CHECK(full->port == 8443);
    CHECK(full->path == "/f3a9c2e1b7d4");
    CHECK(full->tls);
    CHECK(full->fingerprint == kFingerprint);
    CHECK(full->toString() == "https://gate.example:8443/f3a9c2e1b7d4#" + kFingerprint);

    const std::optional<GatewayAddress> standard = parsed("https://gate.example/secret");
    CHECK(standard.has_value() && standard->port == 443);
    CHECK(standard->toString() == "https://gate.example/secret#" + kFingerprint);

    const std::optional<GatewayAddress> plain = parsed("http://203.0.113.5/secret");
    CHECK(plain.has_value() && !plain->tls && plain->port == 80);
    CHECK(plain->host == "203.0.113.5");
    CHECK(plain->toString() == "http://203.0.113.5/secret#" + kFingerprint);

    const std::optional<GatewayAddress> six = parsed("http://[2001:db8::5]:8080/secret");
    CHECK(six.has_value() && six->host == "2001:db8::5" && six->port == 8080);
    CHECK(six->toString() == "http://[2001:db8::5]:8080/secret#" + kFingerprint);
    const std::optional<GatewayAddress> sixPlain = parsed("https://[::1]/secret");
    CHECK(sixPlain.has_value() && sixPlain->host == "::1" && sixPlain->port == 443);

    const std::optional<GatewayAddress> deep = parsed("https://gate.example/one/two/three");
    CHECK(deep.has_value() && deep->path == "/one/two/three");

    CHECK(!GatewayAddress::parse("").has_value());
    CHECK(!parsed("gate.example/secret").has_value());
    CHECK(!parsed("ftp://gate.example/secret").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example/secret").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example/secret#").has_value());
    CHECK(!GatewayAddress::parse("https://gate.example/secret#a-token").has_value());
    CHECK(!parsed("https://gate.example").has_value());
    CHECK(!parsed("https://gate.example/").has_value());
    CHECK(!parsed("https:///secret").has_value());
    CHECK(!parsed("https://gate.example:http/secret").has_value());
    CHECK(!parsed("https://gate.example:0/secret").has_value());
    CHECK(!parsed("https://gate.example:70000/secret").has_value());
    CHECK(!parsed("http://[not-an-address]/secret").has_value());
    CHECK(!parsed("http://[2001:db8::5/secret").has_value());
    CHECK(!parsed("http://2001:db8::5/secret").has_value());

    const std::string handed = six->link();
    CHECK(handed
        == "https://bazari.sh/#gateway?v=2&url=http://[2001:db8::5]:8080/secret&fp=" + kFingerprint);
    const std::optional<GatewayAddress> taken = GatewayAddress::fromLink(handed);
    CHECK(taken.has_value() && taken->toString() == six->toString());
    const std::optional<GatewayAddress> scheme = GatewayAddress::fromLink(
        "bazarish://gateway?v=2&url=https://127.0.0.1:8431/secret&fp=" + kFingerprint);
    CHECK(scheme.has_value() && scheme->port == 8431);
    CHECK(!GatewayAddress::fromLink("bazarish://gateway?v=1&url=https://127.0.0.1:8431/secret&fp="
        + kFingerprint)
               .has_value());
    CHECK(!GatewayAddress::fromLink(
        "https://bazari.sh/#gateway?v=2&url=https://g.example/p&token=t").has_value());
    CHECK(!GatewayAddress::fromLink("https://bazari.sh/#gateway?v=2&url=https://g.example/p")
            .has_value());
    CHECK(!GatewayAddress::fromLink(
        "https://bazari.sh/#gateway?v=2&url=https://g.example/p#x&fp=" + kFingerprint)
               .has_value());
    CHECK(!GatewayAddress::fromLink(
        "https://bazari.sh/#invite?v=2&url=https://g.example/p&fp=" + kFingerprint)
               .has_value());

    std::printf("TestGatewayAddress ok\n");
    return 0;
}
