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
    const Bytes srvKey = Key::generateSealing().publicDer();  // a real SPKI

    const Descriptor original{fp, srv, srvKey};
    const std::string uri = encodeDescriptor(original);
    CHECK(uri.rfind("bazarish://invite?v=1&", 0) == 0);

    const Descriptor parsed = parseDescriptor(uri);
    CHECK(parsed.fingerprint == fp);
    CHECK(parsed.srv == srv);
    CHECK(parsed.srvKeyDer == srvKey);

    const auto rejects = [](const std::string& bad) {
        try {
            (void)parseDescriptor(bad);
        } catch (const std::exception&) {
            return true;
        }
        return false;
    };

    CHECK(rejects("https://example.com"));                                               // wrong scheme
    CHECK(rejects("bazarish://invite?fp=" + fp + "&srv=" + srv));                         // missing v, srv_key
    CHECK(rejects("bazarish://invite?v=2&fp=" + fp + "&srv=" + srv + "&srv_key=AAAA"));   // bad version
    CHECK(rejects("bazarish://invite?v=1&fp=tooShort&srv=" + srv + "&srv_key=AAAA"));     // bad fingerprint
    CHECK(rejects("bazarish://invite?v=1&fp=" + fp + "&srv=stats.i2p&srv_key=AAAA"));     // not .b32.i2p
    CHECK(rejects("bazarish://invite?v=1&fp=" + fp + "&srv=" + srv + "&srv_key="));       // empty key

    std::printf("TestDescriptor: all checks passed\n");
    return 0;
}
