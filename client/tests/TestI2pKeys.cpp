// Bazarish project (c) 2026
#include "I2pKeys.hpp"
#include "Session.hpp"

#include <bazarish/Bytes.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
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

namespace {

// A fresh master is well-formed and its serialized form re-derives the same
// stable address.
void testMasterRoundTrip()
{
    const I2pMasterKey master = generateI2pMaster();
    CHECK(!master.privateKeys.empty());
    CHECK(master.base32.size() == 52);  // 256-bit ident hash, base32, no padding
    CHECK(i2pBase32(master.privateKeys) == master.base32);
}

// Two masters are different identities.
void testMastersDiffer()
{
    const I2pMasterKey a = generateI2pMaster();
    const I2pMasterKey b = generateI2pMaster();
    CHECK(a.base32 != b.base32);
}

// Offline (transient) keys operate the SAME destination as the master, and a
// second transient yields the same address again - the migration property:
// the user keeps one address while each operator gets its own short-lived key.
void testOfflineKeepsAddress()
{
    const I2pMasterKey master = generateI2pMaster();
    const std::int64_t expires = 1893456000;  // 2030-01-01, comfortably in range

    const Bytes operatorA = issueI2pOfflineKeys(master.privateKeys, expires);
    const Bytes operatorB = issueI2pOfflineKeys(master.privateKeys, expires);
    CHECK(!operatorA.empty());
    CHECK(!operatorB.empty());
    CHECK(operatorA != operatorB);  // distinct transients
    CHECK(i2pBase32(operatorA) == master.base32);
    CHECK(i2pBase32(operatorB) == master.base32);

    // The I2P-base64 form (the blob handed to the serving server's I2P router) is
    // non-empty, deterministic for a given transient, and distinct per transient.
    const std::string b64A = i2pPrivateKeysBase64(operatorA);
    CHECK(!b64A.empty());
    CHECK(i2pPrivateKeysBase64(operatorA) == b64A);
    CHECK(i2pPrivateKeysBase64(operatorB) != b64A);
}

// Malformed input is rejected, not silently accepted.
void testMalformedRejected()
{
    bool threw = false;
    try {
        const Bytes garbage = {0x00, 0x01, 0x02, 0x03};
        (void)i2pBase32(garbage);
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
}

// An existing master blob (a user's ".dat") loads back to the same identity,
// and a malformed blob is rejected.
void testLoadMaster()
{
    const I2pMasterKey master = generateI2pMaster();
    const I2pMasterKey loaded = loadI2pMaster(master.privateKeys);
    CHECK(loaded.base32 == master.base32);
    CHECK(i2pBase32(loaded.privateKeys) == master.base32);

    bool threw = false;
    try {
        (void)loadI2pMaster(Bytes{0x00, 0x01, 0x02, 0x03});
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
}

// A account with no destination adopts an existing master from a .dat blob; the
// address persists across reopen, and a second load is refused (a different key
// would change the user's address).
void testSessionLoadsDat()
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("bazarish-i2pload-" + toHex(randomBytes(8)));
    const I2pMasterKey existing = generateI2pMaster();

    {
        Session session = Session::create(dir, "pw", "carol");
        CHECK(!session.hasI2pDestination());
        const std::string address = session.loadI2pDestination(existing.privateKeys);
        CHECK(address == existing.base32);
        CHECK(session.hasI2pDestination());

        bool threw = false;
        try {
            (void)session.loadI2pDestination(generateI2pMaster().privateKeys);
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);  // already configured
    }
    {
        const Session session = Session::open(dir, "pw");
        CHECK(session.i2pAddress() == existing.base32);  // adopted key persisted
    }
    fs::remove_all(dir);
}

// A session opts into a user-owned destination, the master persists sealed at
// rest across reopen, and the transient delegation tracks the same address.
void testSessionPersistsAndDelegates()
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("bazarish-i2p-" + toHex(randomBytes(8)));

    std::string address;
    {
        Session session = Session::create(dir, "pw", "alice");
        CHECK(!session.hasI2pDestination());  // free accounts use the server pool
        address = session.ensureI2pDestination();
        CHECK(address.size() == 52);
        CHECK(session.hasI2pDestination());
        CHECK(session.i2pAddress() == address);
        session.renewI2pTransient(1893456000);
        CHECK(!session.i2pTransient().empty());
        CHECK(i2pBase32(session.i2pTransient()) == address);
    }
    {
        const Session session = Session::open(dir, "pw");
        CHECK(session.hasI2pDestination());
        CHECK(session.i2pAddress() == address);  // master persisted, same address
        CHECK(i2pBase32(session.i2pTransient()) == address);  // transient restored
    }
    fs::remove_all(dir);
}

}  // namespace

int main()
{
    testMasterRoundTrip();
    testMastersDiffer();
    testOfflineKeepsAddress();
    testMalformedRejected();
    testLoadMaster();
    testSessionLoadsDat();
    testSessionPersistsAndDelegates();
    std::printf("TestI2pKeys: all checks passed\n");
    return 0;
}
