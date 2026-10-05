// Bazarish project (c) 2026
#include "Qr.hpp"
#include "Session.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Descriptor.hpp>

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <stdexcept>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

namespace {

namespace fs = std::filesystem;

fs::path uniqueAccountFile(const std::string& tag)
{
    const fs::path dir
        = fs::temp_directory_path() / ("bazarish-test-" + tag + "-" + toHex(randomBytes(8)));
    fs::create_directories(dir);
    return dir / "account.db";
}

}  // namespace

int main()
{

    const Identity serverIdentity = Identity::generate();
    const std::string serverFp = serverIdentity.fingerprint();
    const Key servingKey = Key::generateSealing();
    const std::string userDest = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
    const Identity user = Identity::generate();

    const std::string view = "0123456789abcdef0123456789abcdef";
    const Descriptor descriptor{user.fingerprint(), userDest, view};
    const std::string uri = encodeDescriptor(descriptor);
    CHECK(uri.rfind("bazarish://invite?", 0) == 0);

    const Descriptor decoded = parseDescriptor(uri);
    CHECK(decoded.fingerprint == user.fingerprint());
    CHECK(decoded.dest == userDest);
    CHECK(decoded.view == view);

    CHECK_THROWS(parseDescriptor("http://example/x"));
    CHECK_THROWS(parseDescriptor("bazarish://invite?v=1&fp=short"));

    const std::vector<std::string> codes = renderQrCodes(uri);
    CHECK(!codes.empty());
    for (const std::string& code : codes) {
        CHECK(!code.empty());
    }

    ServerEndpoint endpoint;
    endpoint.serverFingerprint = serverFp;
    endpoint.facades = {Facade{false, "127.0.0.1", 9, {}}};

    const fs::path fileA = uniqueAccountFile("a");
    const std::string passphrase = "at-rest secret";
    const std::string fingerprintA = Session::create(fileA, endpoint, passphrase).fingerprint();

    CHECK_THROWS(Session::open(fileA));
    CHECK_THROWS(Session::open(fileA, "wrong"));
    CHECK(Session::open(fileA, passphrase).fingerprint() == fingerprintA);

    const fs::path bundle = uniqueAccountFile("bundle").parent_path() / "session.baz";
    const std::string exportPw = "export password";
    Session::open(fileA, passphrase).exportAccount(bundle, exportPw);

    const fs::path fileB = uniqueAccountFile("b");
    CHECK_THROWS(Session::importAccount(bundle, fileB, "bad password"));
    Session::importAccount(bundle, fileB, exportPw);
    CHECK(Session::open(fileB).fingerprint() == fingerprintA);
    CHECK(Session::open(fileB).deliveryIdFor("some-message", "some-mailbox")
        == Session::open(fileA, passphrase).deliveryIdFor("some-message", "some-mailbox"));

    const fs::path fileC = uniqueAccountFile("c");
    Session::importAccount(bundle, fileC, exportPw, "new at-rest");
    CHECK_THROWS(Session::open(fileC));
    CHECK(Session::open(fileC, "new at-rest").fingerprint() == fingerprintA);

    fs::remove_all(fileA);
    fs::remove_all(fileB);
    fs::remove_all(fileC);
    fs::remove_all(bundle.parent_path());

    std::fprintf(stderr, "TestInvite passed\n");
    return 0;
}
