// Bazarish project (c) 2026
#include "AccountDb.hpp"
#include "AccountManager.hpp"
#include "Session.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/PathText.hpp>

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

using namespace bazarish;
using namespace bazarish::client;

int main()
{
    namespace fs = std::filesystem;
    const fs::path root
        = fs::temp_directory_path() / ("bazarish-accounts-" + toHex(randomBytes(8)));

    AccountManager manager(root);
    CHECK(manager.list().empty());

    const AccountInfo a = manager.create("Acetone", AccountKind::eUser, "secret");
    CHECK(a.id != "Acetone");
    CHECK(!a.id.empty());
    CHECK(a.name == "Acetone");
    CHECK(a.encrypted);
    CHECK(a.fingerprint.size() == kFingerprintTextLength);

    const AccountInfo b = manager.create("Work Alias", AccountKind::eUser);
    CHECK(b.id != a.id);
    CHECK(b.name == "Work Alias");
    CHECK(!b.encrypted);

    const AccountInfo twin = manager.create("Work Alias", AccountKind::eUser);
    CHECK(twin.id != b.id);
    CHECK(twin.name == "Work Alias");

    const AccountInfo cyrillic = manager.create("клирнет", AccountKind::eUser);
    CHECK(cyrillic.name == "клирнет");
    const AccountInfo slashed = manager.create("home/work: notes", AccountKind::eUser);
    CHECK(slashed.name == "home/work: notes");

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
    for (const std::filesystem::directory_entry& entry :
        std::filesystem::directory_iterator(root)) {
        const std::string stem = entry.path().stem().string();
        CHECK(stem.find("Acetone") == std::string::npos);
        CHECK(stem.find("Work") == std::string::npos);
        CHECK(stem.find("клирнет") == std::string::npos);
    }

    CHECK_THROWS(manager.open(a.id));
    {
        Session sa = manager.open(a.id, "secret");
        CHECK(sa.fingerprint() == a.fingerprint);
        CHECK(sa.displayName() == "Acetone");
        CHECK(!sa.isConnected());

        ServerEndpoint endpoint;
        endpoint.serverFingerprint = "serverfp";
        endpoint.facades = {Facade{"127.0.0.1", 18000}};
        sa.connectServer(endpoint);
        CHECK(sa.isConnected());
        CHECK(sa.endpoint().facades.at(0).port == 18000);

        bool foundLocked = false;
        for (const AccountInfo& info : manager.list()) {
            if (info.id == a.id) {
                CHECK(info.encrypted);
                CHECK(info.fingerprint.empty());
                foundLocked = true;
            }
        }
        CHECK(foundLocked);

        CHECK(sa.acceptCalls());
        CHECK(sa.sendReceipts());
        sa.setSendReceipts(false);
        sa.setAcceptCalls(false);

        const Session reopened = manager.open(a.id, "secret");
        CHECK(reopened.isConnected());
        CHECK(reopened.endpoint().serverFingerprint == "serverfp");
        CHECK(!reopened.sendReceipts());
        CHECK(!reopened.acceptCalls());

        {
            AccountDb db(a.file, "secret");
            nlohmann::json meta = nlohmann::json::parse(db.text("meta"));
            meta["endpoint"]["facades"] = {"http://abc.b32.i2p/s/9f3c"};
            db.putText("meta", meta.dump());
        }
        {
            Session unusable = manager.open(a.id, "secret");
            CHECK(!unusable.isConnected());
            CHECK(unusable.endpoint().serverFingerprint == "serverfp");
            CHECK(!unusable.sendReceipts());
            unusable.connectServer(endpoint);
            CHECK(unusable.isConnected());
        }
        CHECK(manager.open(a.id, "secret").endpoint().facades.at(0).port == 18000);

        const auto onlyTheDatabase = [](const fs::path& file) {
            CHECK(fs::is_regular_file(file));
            CHECK(fs::is_regular_file(fs::path(file).replace_extension(".key")));
            for (const fs::directory_entry& entry : fs::directory_iterator(file.parent_path())) {
                const std::string extension = entry.path().extension().string();
                CHECK(extension == ".db" || extension == ".key" || extension == ".bundle");
            }
        };

        const fs::path scratch
            = fs::temp_directory_path() / ("bazarish-export-" + toHex(randomBytes(8)));
        fs::create_directories(scratch);
        const fs::path bundle = scratch / "acetone.bundle";
        const Bytes face = {'P', 'N', 'G', 0x01, 0x02, 0x03};
        sa.setAvatar(face, "image/png");
        sa.exportAccount(bundle, "bundle-pw");

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
            CHECK(!fs::exists(root2 / ".import-tmp.db"));

            sa.ensureI2pDestination();
            const AddressKeys addressKeys = sa.addressKeys();
            const Bytes sealed = sa.exportAccountBytes("bundle-pw");
            CHECK(!sealed.empty());
            Session::importAccountBytes(sealed, scratch / "imported-mem.db", "bundle-pw",
                "atrest-pw");
            onlyTheDatabase(scratch / "imported-mem.db");
            Session importedMem = Session::open(scratch / "imported-mem.db", "atrest-pw");
            CHECK(importedMem.fingerprint() == a.fingerprint);
            CHECK(importedMem.i2pAddress() == sa.i2pAddress());
            CHECK(importedMem.addressKeys().sealingPem == addressKeys.sealingPem);
            CHECK(importedMem.addressKeys().signingPem == addressKeys.signingPem);
            CHECK(importedMem.avatarMime() == "image/png");
            CHECK(importedMem.avatar() == face);
            CHECK_THROWS(
                Session::importAccountBytes(sealed, scratch / "refused.db", "wrong-pw"));
            CHECK(!fs::exists(scratch / "refused.db"));

            const AccountInfo imp3 = manager2.import("", sealed, "bundle-pw");
            CHECK(imp3.name == "Acetone");
            CHECK(imp3.fingerprint == a.fingerprint);
            CHECK(manager2.list().size() == 3);
            CHECK(!fs::exists(root2 / ".import-tmp.db"));

            const std::string headerOnly = R"({"v":1})";
            const Bytes sealedHeaderOnly = cms::sealWithPassword(
                Bytes(headerOnly.begin(), headerOnly.end()), "bundle-pw");
            CHECK_THROWS(manager2.import("", sealedHeaderOnly, "bundle-pw"));
            CHECK(manager2.list().size() == 3);
            CHECK(!fs::exists(root2 / ".import-tmp.db"));
            fs::remove_all(root2);

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
                constexpr std::streamoff kMemoryCostOffset = 4;
                std::fstream out(fs::path(costly).replace_extension(".key"),
                    std::ios::binary | std::ios::in | std::ios::out);
                out.seekp(kMemoryCostOffset);
                const char every[] = {'\xFF', '\xFF', '\xFF', '\xFF'};
                out.write(every, sizeof every);
            }
            bool costRefused = false;
            try {
                (void)Session::open(costly);
            } catch (const std::exception& error) {
                costRefused = std::string(error.what()).find("derivation cost") != std::string::npos;
            }
            CHECK(costRefused);
        }

        fs::remove_all(scratch);

        manager.remove(b.id);
        CHECK(!manager.exists(b.id));
        CHECK(manager.list().size() == 4);
    }

    {
        const fs::path named = root / pathFromUtf8("Профиль.db");
        {
            AccountDb db(named, "secret");
            db.putText("probe", "value");
        }
        CHECK(fs::exists(named));
        CHECK(AccountDb(named, "secret").text("probe") == "value");
    }

    {
        const fs::path kinds = root / "kinds";
        fs::create_directories(kinds);

        Session user = Session::create(kinds / "user.db", AccountKind::eUser);
        CHECK(user.kind() == AccountKind::eUser);
        CHECK(user.presenceKey().rawPrivate().size() == 32);
        CHECK(!user.presenceDest().empty());
        const std::string userPresence = user.presenceDest();
        const Bytes userBundle = user.exportAccountBytes("pw");
        CHECK(Session::bundleKind(userBundle, "pw") == AccountKind::eUser);
        Session::importAccountBytes(userBundle, kinds / "user-copy.db", "pw");
        const Session userCopy = Session::open(kinds / "user-copy.db");
        CHECK(userCopy.kind() == AccountKind::eUser);
        CHECK(userCopy.presenceDest() == userPresence);
        CHECK(userCopy.presenceKey().rawPrivate() == user.presenceKey().rawPrivate());

        Session bot = Session::create(kinds / "bot.db", AccountKind::eBot);
        CHECK(bot.kind() == AccountKind::eBot);
        CHECK(bot.presenceDest().empty());
        CHECK_THROWS(bot.presenceKey());
        const Bytes botBundle = bot.exportAccountBytes("pw");
        CHECK(Session::bundleKind(botBundle, "pw") == AccountKind::eBot);
        Session::importAccountBytes(botBundle, kinds / "bot-copy.db", "pw");
        CHECK(Session::open(kinds / "bot-copy.db").kind() == AccountKind::eBot);

        const auto dropKind = [](const fs::path& file) {
            AccountDb db(file, std::string{});
            nlohmann::json meta = nlohmann::json::parse(db.text("meta"));
            meta.erase("kind");
            db.putText("meta", meta.dump());
        };
        dropKind(kinds / "user-copy.db");
        CHECK_THROWS(Session::open(kinds / "user-copy.db"));
        CHECK_THROWS(Session::assignHostedKind(kinds / "user-copy.db", AccountKind::eUser));

        dropKind(kinds / "bot-copy.db");
        CHECK_THROWS(Session::open(kinds / "bot-copy.db"));
        Session::assignHostedKind(kinds / "bot-copy.db", AccountKind::eBot);
        CHECK(Session::open(kinds / "bot-copy.db").kind() == AccountKind::eBot);
        Session::assignHostedKind(kinds / "bot-copy.db", AccountKind::eBot);
        CHECK_THROWS(Session::assignHostedKind(kinds / "bot-copy.db", AccountKind::eChat));

        {
            AccountDb db(kinds / "user.db", std::string{});
            db.erase("presence-dest");
        }
        CHECK_THROWS(Session::open(kinds / "user.db"));
    }

    fs::remove_all(root);

#ifndef _WIN32
    if (const char* const home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
        CHECK(::setenv("XDG_DATA_HOME", "/tmp/bazarish-not-this-one", 1) == 0);
        CHECK(AccountManager::globalRoot()
            == fs::path(home) / ".local" / "share" / "bazarish");
    }
#endif

    std::fprintf(stderr, "TestAccount passed\n");
    return 0;
}
