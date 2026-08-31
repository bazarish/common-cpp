// Bazarish project (c) 2026
#include "AccountManager.hpp"
#include "Session.hpp"

#include <bazarish/Bytes.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
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

#define CHECK_THROWS(expression)                                                     \
    do {                                                                             \
        bool thrown = false;                                                         \
        try {                                                                        \
            (void)(expression);                                                      \
        } catch (const std::exception&) {                                            \
            thrown = true;                                                           \
        }                                                                            \
        if (!thrown) {                                                               \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d\n", __FILE__, __LINE__); \
            std::exit(1);                                                            \
        }                                                                            \
    } while (false)

using namespace bazarish;
using namespace bazarish::client;

int main()
{
    namespace fs = std::filesystem;
    const fs::path root
        = fs::temp_directory_path() / ("bazarish-accounts-" + toHex(randomBytes(8)));

    AccountManager manager(root);
    CHECK(manager.list().empty());

    // Create two accounts, one encrypted. A account is one file named after it,
    // so the name is the id.
    const AccountInfo a = manager.create("Acetone", "secret");
    CHECK(a.id == "Acetone");
    CHECK(a.name == "Acetone");
    CHECK(a.encrypted);
    CHECK(!a.connected);
    CHECK(a.fingerprint.size() == kFingerprintTextLength);

    const AccountInfo b = manager.create("Work Alias");
    CHECK(b.id == "Work Alias");
    CHECK(!b.encrypted);

    // A repeat of a name is a repeat of a file name, locked or not.
    CHECK_THROWS(manager.create("Work Alias"));
    CHECK_THROWS(manager.create("Acetone", "other"));

    // The name is kept as it was typed, Unicode and all; only what a file system
    // refuses is replaced.
    const AccountInfo cyrillic = manager.create("клирнет");
    CHECK(cyrillic.id == "клирнет");
    CHECK(cyrillic.name == "клирнет");
    const AccountInfo slashed = manager.create("home/work: notes");
    CHECK(slashed.id == "home_work_ notes");

    // Listing gives up nothing about a account that has a passphrase: everything
    // it could say lives inside the keyed database. It is listed by its directory
    // id, marked locked, with no fingerprint. A account without a passphrase opens
    // with the default key, so its name and fingerprint do show.
    CHECK(manager.list().size() == 4);
    for (const AccountInfo& listed : manager.list()) {
        if (listed.id == "Acetone") {
            CHECK(listed.encrypted);
            CHECK(listed.fingerprint.empty());
        }
        if (listed.id == "Work Alias") {
            CHECK(!listed.encrypted);
            CHECK(!listed.fingerprint.empty());
        }
    }

    // Encrypted account needs its passphrase to open.
    CHECK_THROWS(manager.open("Acetone"));
    // The root goes once every session opened from it is gone, for the same
    // reason.
    {
        Session sa = manager.open("Acetone", "secret");
        CHECK(sa.fingerprint() == a.fingerprint);
        CHECK(sa.displayName() == "Acetone");
        CHECK(!sa.isConnected());

        // Connecting a account to a server persists the endpoint and flips the
        // connected flag seen by the picker.
        ServerEndpoint endpoint;
        endpoint.serverFingerprint = "serverfp";
        endpoint.facades = {Facade{false, "127.0.0.1", 18000, {}}};
        sa.connectServer(endpoint);
        CHECK(sa.isConnected());
        CHECK(sa.endpoint().facades.at(0).port == 18000);

        // Whether a locked account has a server is part of what its database keeps,
        // so the listing cannot say: it only reports the account as locked. With the
        // passphrase in hand the full picture is there.
        bool foundLocked = false;
        for (const AccountInfo& info : manager.list()) {
            if (info.id == "Acetone") {
                CHECK(info.encrypted);
                CHECK(!info.connected);
                foundLocked = true;
            }
        }
        CHECK(foundLocked);

        // The account's own answers are the account's, not the window's: they are
        // written down and are the same the next time it is opened.
        CHECK(sa.acceptCalls());
        CHECK(sa.sendReceipts());
        sa.setSendReceipts(false);
        sa.setAcceptCalls(false);

        // Reopening preserves the connection and label.
        const Session reopened = manager.open("Acetone", "secret");
        CHECK(reopened.isConnected());
        CHECK(reopened.endpoint().serverFingerprint == "serverfp");
        CHECK(!reopened.sendReceipts());
        CHECK(!reopened.acceptCalls());

        // Export the encrypted account, then re-import it twice - once with an
        // at-rest passphrase, once without - and check that each import is one keyed
        // database that opens with its own key and nothing else.
        // A account is its database plus the small key file beside it, and nothing
        // else: an import writes exactly that pair.
        const auto onlyTheDatabase = [](const fs::path& file) {
            CHECK(fs::is_regular_file(file));
            CHECK(fs::is_regular_file(fs::path(file).replace_extension(".key")));
            for (const fs::directory_entry& entry : fs::directory_iterator(file.parent_path())) {
                const std::string extension = entry.path().extension().string();
                CHECK(extension == ".db" || extension == ".key" || extension == ".bundle");
            }
        };

        // Kept outside the manager root so the imported accounts do not show up in
        // manager.list().
        const fs::path scratch
            = fs::temp_directory_path() / ("bazarish-export-" + toHex(randomBytes(8)));
        fs::create_directories(scratch);
        const fs::path bundle = scratch / "acetone.bundle";
        sa.exportAccount(bundle, "bundle-pw");

        // The scratch directory goes once the sessions reading from it are gone: an
        // open database file is not one every platform lets go of.
        {
            Session::importAccount(bundle, scratch / "imported-enc.db", "bundle-pw", "atrest-pw");
            onlyTheDatabase(scratch / "imported-enc.db");
            const Session importedEnc = Session::open(scratch / "imported-enc.db", "atrest-pw");
            CHECK(importedEnc.fingerprint() == a.fingerprint);
            CHECK_THROWS(Session::open(scratch / "imported-enc.db"));

            Session::importAccount(bundle, scratch / "imported-plain.db", "bundle-pw");
            onlyTheDatabase(scratch / "imported-plain.db");
            const Session importedPlain = Session::open(scratch / "imported-plain.db");
            CHECK(importedPlain.fingerprint() == a.fingerprint);

            // Importing through a manager restores the display name from the bundle. With
            // no explicit name the on-disk id is derived from that restored name; an
            // explicit name only chooses the id (the display name still comes from the
            // bundle). Use a fresh root so the derived "acetone" id does not collide.
            const fs::path root2
                = fs::temp_directory_path() / ("bazarish-accounts-" + toHex(randomBytes(8)));
            AccountManager manager2(root2);
            const AccountInfo imp1 = manager2.import("", bundle, "bundle-pw");
            CHECK(imp1.id == "Acetone");
            CHECK(imp1.name == "Acetone");
            CHECK(imp1.fingerprint == a.fingerprint);
            const AccountInfo imp2 = manager2.import("Other Name", bundle, "bundle-pw");
            CHECK(imp2.id == "Other Name");
            CHECK(imp2.name == "Acetone");
            CHECK(manager2.list().size() == 2);
            CHECK(!fs::exists(root2 / ".import-tmp"));
            fs::remove_all(root2);

            // The key file is a record of one exact size naming the cost of opening the
            // account. Neither is taken from disk on trust: a file of another size is
            // not this format, and a cost beyond what the derivation may be asked for is
            // refused rather than spent. Copies are used because the unwrapped key is
            // remembered per database path, and a path already opened would not read its
            // key file again.
            const auto copyOfPlainAccount = [&scratch](const std::string& name) {
                const fs::path database = scratch / (name + ".db");
                fs::copy_file(scratch / "imported-plain.db", database);
                fs::copy_file(scratch / "imported-plain.key", fs::path(database).replace_extension(".key"));
                return database;
            };

            const fs::path padded = copyOfPlainAccount("padded");
            {
                std::ofstream out(
                    fs::path(padded).replace_extension(".key"), std::ios::binary | std::ios::app);
                out << 'x';
            }
            CHECK_THROWS(Session::open(padded));

            const fs::path costly = copyOfPlainAccount("costly");
            {
                // The memory cost is the first field after the four-byte magic, little
                // endian; asking for every kibibyte a 32-bit field can name is four
                // terabytes of derivation memory.
                constexpr std::streamoff kMemoryCostOffset = 4;
                std::fstream out(fs::path(costly).replace_extension(".key"),
                    std::ios::binary | std::ios::in | std::ios::out);
                out.seekp(kMemoryCostOffset);
                const char every[] = {'\xFF', '\xFF', '\xFF', '\xFF'};
                out.write(every, sizeof every);
            }
            // The message matters here: the cost has to be refused on sight, not found
            // out by trying to spend it.
            bool costRefused = false;
            try {
                (void)Session::open(costly);
            } catch (const std::exception& error) {
                costRefused = std::string(error.what()).find("derivation cost") != std::string::npos;
            }
            CHECK(costRefused);
        }

        fs::remove_all(scratch);

        // Removal drops the account.
        manager.remove("Work Alias");
        CHECK(!manager.exists("Work Alias"));
        CHECK(manager.list().size() == 3);
    }

    fs::remove_all(root);
    std::fprintf(stderr, "TestAccount passed\n");
    return 0;
}
