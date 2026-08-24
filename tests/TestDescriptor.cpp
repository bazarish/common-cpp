// Bazarish project (c) 2026
#include "bazarish/Descriptor.hpp"

#include "bazarish/Crypto.hpp"

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
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

int main()
{
    // A 52-char base32 fingerprint and a valid .b32.i2p serving host.
    const std::string fp = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq";
    const std::string srv = "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
    const std::string view = "0123456789abcdef0123456789abcdef";  // a card-read capability

    const Descriptor original{fp, srv, view};
    const std::string uri = encodeDescriptor(original);
    CHECK(uri.rfind("bazarish://invite?v=1&", 0) == 0);

    const Descriptor parsed = parseDescriptor(uri);
    CHECK(parsed.fingerprint == fp);
    CHECK(parsed.dest == srv);
    CHECK(parsed.view == view);
    CHECK(parsed.name.empty());  // no name advertised

    // The optional name round-trips through percent-encoding, including the
    // characters that would otherwise break the '&'/'=' split, and UTF-8.
    Descriptor named{fp, srv, view};
    named.name = "Ann & Bob = friends \xD0\x9C\xD0\xB0\xD1\x88\xD0\xB0";  // "Маша" in UTF-8
    const std::string namedUri = encodeDescriptor(named);
    const Descriptor namedParsed = parseDescriptor(namedUri);
    CHECK(namedParsed.fingerprint == fp);
    CHECK(namedParsed.dest == srv);
    CHECK(namedParsed.view == view);
    CHECK(namedParsed.name == named.name);

    const auto rejects = [](const std::string& bad) {
        try {
            (void)parseDescriptor(bad);
        } catch (const std::exception&) {
            return true;
        }
        return false;
    };

    CHECK(rejects("https://example.com"));                                               // wrong scheme
    CHECK(rejects("bazarish://invite?fp=" + fp + "&dest=" + srv));                         // missing v, srv_key
    CHECK(rejects("bazarish://invite?v=2&fp=" + fp + "&dest=" + srv + "&key=AAAA"));   // bad version
    CHECK(rejects("bazarish://invite?v=1&fp=tooShort&dest=" + srv + "&key=AAAA"));     // bad fingerprint
    CHECK(rejects("bazarish://invite?v=1&fp=" + fp + "&dest=stats.i2p&key=AAAA"));     // not .b32.i2p
    CHECK(rejects("bazarish://invite?v=1&fp=" + fp + "&dest=" + srv + "&key="));       // empty key

    std::printf("TestDescriptor: all checks passed\n");
    return 0;
}
