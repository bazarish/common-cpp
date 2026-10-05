// Bazarish project (c) 2026
#include "I2pKeys.hpp"
#include "Session.hpp"

#include <bazarish/Bytes.hpp>

#include "TestUtil.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

namespace {

// A blinded b33 label is 56 base32 characters, plus ".b32.i2p".
constexpr std::size_t kB33HostLen = 56 + 8;
constexpr int kTermDays = 2;

void testMasterRoundTrip()
{
    const I2pMasterKey master = generateI2pMaster();
    CHECK(!master.privateKeys.empty());
    CHECK(master.host.size() == kB33HostLen);
    CHECK(i2pRoutingHost(master.privateKeys) == master.host);
}

void testMastersDiffer()
{
    const I2pMasterKey a = generateI2pMaster();
    const I2pMasterKey b = generateI2pMaster();
    CHECK(a.host != b.host);
}

void testOfflineKeepsAddress()
{
    const I2pMasterKey master = generateI2pMaster();

    const Bytes operatorA = issueI2pOfflineKeys(master.privateKeys, kTermDays);
    const Bytes operatorB = issueI2pOfflineKeys(master.privateKeys, kTermDays);
    CHECK(!operatorA.empty());
    CHECK(!operatorB.empty());
    CHECK(operatorA != operatorB);
    CHECK(i2pRoutingHost(operatorA) == master.host);
    CHECK(i2pRoutingHost(operatorB) == master.host);
    CHECK(i2pDelegationExpires(operatorA) == i2pDelegationExpires(operatorB));
    CHECK(i2pDelegationExpires(operatorA) > 0);
    CHECK(i2pDelegationExpires(master.privateKeys) == 0);

    const std::string b64A = i2pPrivateKeysBase64(operatorA);
    CHECK(!b64A.empty());
    CHECK(i2pPrivateKeysBase64(operatorA) == b64A);
    CHECK(i2pPrivateKeysBase64(operatorB) != b64A);
}

void testMalformedRejected()
{
    bool threw = false;
    try {
        const Bytes garbage = {0x00, 0x01, 0x02, 0x03};
        (void)i2pRoutingHost(garbage);
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
}

void testLoadMaster()
{
    const I2pMasterKey master = generateI2pMaster();
    const I2pMasterKey loaded = loadI2pMaster(master.privateKeys);
    CHECK(loaded.host == master.host);
    CHECK(i2pRoutingHost(loaded.privateKeys) == master.host);

    bool threw = false;
    try {
        (void)loadI2pMaster(Bytes{0x00, 0x01, 0x02, 0x03});
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
}

void testSessionLoadsDat()
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("bazarish-i2pload-" + toHex(randomBytes(8)));
    const I2pMasterKey existing = generateI2pMaster();

    {
        Session session = Session::create(dir, "pw", "carol");
        CHECK(!session.hasI2pDestination());
        const std::string address = session.loadI2pDestination(existing.privateKeys);
        CHECK(address == existing.host);
        CHECK(session.hasI2pDestination());

        bool threw = false;
        try {
            (void)session.loadI2pDestination(generateI2pMaster().privateKeys);
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
    }
    {
        const Session session = Session::open(dir, "pw");
        CHECK(session.i2pAddress() == existing.host);
    }
    fs::remove_all(dir);
}

void testSessionPersistsAndDelegates()
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("bazarish-i2p-" + toHex(randomBytes(8)));

    std::string address;
    {
        Session session = Session::create(dir, "pw", "alice");
        CHECK(!session.hasI2pDestination());
        address = session.ensureI2pDestination();
        CHECK(address.size() == kB33HostLen);
        CHECK(session.hasI2pDestination());
        CHECK(session.i2pAddress() == address);
        const std::int64_t expires = session.renewI2pTransient(kTermDays);
        CHECK(!session.i2pTransient().empty());
        CHECK(i2pRoutingHost(session.i2pTransient()) == address);
        CHECK(i2pDelegationExpires(session.i2pTransient()) == expires);
    }
    {
        const Session session = Session::open(dir, "pw");
        CHECK(session.hasI2pDestination());
        CHECK(session.i2pAddress() == address);
        CHECK(i2pRoutingHost(session.i2pTransient()) == address);
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
