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

    // Create two accounts, one encrypted. An account is one file, and the file is
    // named by nothing: a directory listing is readable without a passphrase, so
    // a file named after its account would hand over the whole roster. The name
    // lives inside the keyed database with everything else.
    const AccountInfo a = manager.create("Acetone", "secret");
    CHECK(a.id != "Acetone");
    CHECK(!a.id.empty());
    CHECK(a.name == "Acetone");
    CHECK(a.encrypted);
    CHECK(a.fingerprint.size() == kFingerprintTextLength);

    const AccountInfo b = manager.create("Work Alias");
    CHECK(b.id != a.id);
    CHECK(b.name == "Work Alias");
    CHECK(!b.encrypted);

    // A name may repeat, because a locked account will not say what it is called
    // and the only honest check would be to open every one of them. Two accounts
    // never share a file.
    const AccountInfo twin = manager.create("Work Alias");
    CHECK(twin.id != b.id);
    CHECK(twin.name == "Work Alias");

    // Nothing about the name reaches the file system, so nothing about it has to
    // be sanitised: what a file name may not hold is not the account's problem.
    const AccountInfo cyrillic = manager.create("клирнет");
    CHECK(cyrillic.name == "клирнет");
    const AccountInfo slashed = manager.create("home/work: notes");
    CHECK(slashed.name == "home/work: notes");

    // A directory listing gives up nothing about an account that has a
    // passphrase - not its fingerprint and, now, not its name either. An account
    // without one opens with the default key, so both do show.
    CHECK(manager.list().size() == 5);
    for (const AccountInfo& listed : manager.list()) {
        if (listed.id == a.id) {
            CHECK(listed.encrypted);
            CHECK(listed.fingerprint.empty());
            CHECK(listed.name.empty());
        }
        if (listed.id == b.id) {
            CHECK(!listed.encrypted);
            CHECK(!listed.fingerprint.empty());
            CHECK(listed.name == "Work Alias");
        }
    }
    // And the folder itself says nothing: no file is named after an account.
    for (const std::filesystem::directory_entry& entry :
        std::filesystem::directory_iterator(root)) {
        const std::string stem = entry.path().stem().string();
        CHECK(stem.find("Acetone") == std::string::npos);
        CHECK(stem.find("Work") == std::string::npos);
        CHECK(stem.find("клирнет") == std::string::npos);
    }

    // Encrypted account needs its passphrase to open.
    CHECK_THROWS(manager.open(a.id));
    // The root goes once every session opened from it is gone, for the same
    // reason.
    {
        Session sa = manager.open(a.id, "secret");
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

        // What a listing can say about a locked account is that it is locked:
        // everything else is inside a database nobody has opened.
        bool foundLocked = false;
        for (const AccountInfo& info : manager.list()) {
            if (info.id == a.id) {
                CHECK(info.encrypted);
                CHECK(info.fingerprint.empty());
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
        const Session reopened = manager.open(a.id, "secret");
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
        // A picture is a row of its own in the account, so a bundle that carried
        // only the meta restored a mime with nothing behind it - which the loader
        // then dropped, leaving a restored account with no face at all.
        const Bytes face = {'P', 'N', 'G', 0x01, 0x02, 0x03};
        sa.setAvatar(face, "image/png");
        sa.exportAccount(bundle, "bundle-pw");

        // The scratch directory goes once the sessions reading from it are gone: an
        // open database file is not one every platform lets go of.
        {
            Session::importAccount(bundle, scratch / "imported-enc.db", "bundle-pw", "atrest-pw");
            onlyTheDatabase(scratch / "imported-enc.db");
            const Session importedEnc = Session::open(scratch / "imported-enc.db", "atrest-pw");
            CHECK(importedEnc.fingerprint() == a.fingerprint);
            CHECK(importedEnc.avatarMime() == "image/png");
            CHECK(importedEnc.avatar() == face);
            CHECK_THROWS(Session::open(scratch / "imported-enc.db"));

            Session::importAccount(bundle, scratch / "imported-plain.db", "bundle-pw");
            onlyTheDatabase(scratch / "imported-plain.db");
            const Session importedPlain = Session::open(scratch / "imported-plain.db");
            CHECK(importedPlain.fingerprint() == a.fingerprint);

            // Importing through a manager restores the display name from the
            // bundle. The on-disk id is drawn rather than derived from anything,
            // so the same bundle imported twice is two accounts under two names
            // nobody can read from the folder.
            const fs::path root2
                = fs::temp_directory_path() / ("bazarish-accounts-" + toHex(randomBytes(8)));
            AccountManager manager2(root2);
            const AccountInfo imp1 = manager2.import("", bundle, "bundle-pw");
            CHECK(imp1.id != "Acetone");
            CHECK(imp1.name == "Acetone");
            CHECK(imp1.fingerprint == a.fingerprint);
            const AccountInfo imp2 = manager2.import("Other Name", bundle, "bundle-pw");
            CHECK(imp2.id != imp1.id);
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

        // Removal drops the account, by its id - the only handle there is.
        manager.remove(b.id);
        CHECK(!manager.exists(b.id));
        CHECK(manager.list().size() == 4);
    }

    fs::remove_all(root);

#ifndef _WIN32
    // One data directory, not two: XDG_DATA_HOME named a second place to keep
    // accounts, sounds and settings, and a second place is one the user has to be
    // told about.
    if (const char* const home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
        CHECK(::setenv("XDG_DATA_HOME", "/tmp/bazarish-not-this-one", 1) == 0);
        CHECK(AccountManager::globalRoot()
            == fs::path(home) / ".local" / "share" / "bazarish");
    }
#endif

    std::fprintf(stderr, "TestAccount passed\n");
    return 0;
}
