// Bazarish project (c) 2026
#include "bazarish/KeyedSeal.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <string>

using namespace bazarish;

int main()
{
    const Bytes key = newLinkKey();
    const std::string text = linkKeyText(key);
    CHECK(linkKeyFromText(text) == key);
    CHECK(text.find('=') == std::string::npos);
    CHECK_THROWS(linkKeyFromText(text + "="));
    CHECK_THROWS(linkKeyFromText(text.substr(1)));
    CHECK_THROWS(linkKeyFromText(toBase64Url(Bytes(kLinkKeyBytes - 1, 0))));
    CHECK_THROWS(linkKeyFromText(toBase64(Bytes(kLinkKeyBytes, 0xFB))));
    CHECK_THROWS(linkKeyText(Bytes(kLinkKeyBytes + 1, 0)));

    const Bytes plaintext = {'c', 'a', 'r', 'd'};
    const KeyedSeal asking(key, "request");
    const Bytes sealed = asking.seal(plaintext);
    CHECK(asking.open(sealed) == plaintext);
    CHECK(asking.seal(plaintext) != sealed);
    CHECK(!KeyedSeal(key, "reply").open(sealed).has_value());
    CHECK(!KeyedSeal(newLinkKey(), "request").open(sealed).has_value());
    Bytes tampered = sealed;
    tampered.back() ^= 1;
    CHECK(!asking.open(tampered).has_value());
    CHECK(!asking.open(Bytes(sealed.begin(), sealed.begin() + 4)).has_value());

    std::printf("TestKeyedSeal: all checks passed\n");
    return 0;
}
