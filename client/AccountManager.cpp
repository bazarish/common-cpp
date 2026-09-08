// Bazarish project (c) 2026
#include "AccountManager.hpp"

#include "AccountDb.hpp"
#include "AccountKey.hpp"

#include <bazarish/Limits.hpp>

#include <memory>

#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include <cstdlib>
#include <algorithm>
#include <map>
#include <stdexcept>

namespace bazarish::client {

namespace {

namespace fs = std::filesystem;

// The extension every account file carries.
constexpr const char* kFileSuffix = ".db";

// An account is a pair: the database and the small key file beside it. They move
// and go away together, or the database is left with nothing to open it.
void movePair(const fs::path& from, const fs::path& to)
{
    fs::rename(from, to);
    fs::rename(accountkey::sidecarFor(from), accountkey::sidecarFor(to));
}

void removePair(const fs::path& file)
{
    accountkey::forget(file);
    fs::remove(file);
    fs::remove(accountkey::sidecarFor(file));
}

// How an account is named on disk. Not by its own name: a directory listing is
// readable without any passphrase, so naming the file after the account handed
// the whole roster to anyone who could see the folder - which is the one thing
// the comment below promises it does not do. The name lives inside the keyed
// database with everything else.
constexpr std::size_t kAccountIdBytes = 8;

std::string newAccountId()
{
    return toHex(randomBytes(kAccountIdBytes));
}

// Whether a file name is one of ours rather than an account's own name. Accounts
// used to be stored under their names, and a build that did that may have left
// files behind; they are renamed rather than left to say who they belong to.
bool isAccountId(const std::string& stem)
{
    return stem.size() == kAccountIdBytes * 2
        && std::all_of(stem.begin(), stem.end(), [](const unsigned char c) {
               return std::isxdigit(c) != 0 && (std::isdigit(c) != 0 || std::islower(c) != 0);
           });
}

// What can be told about an account without opening it fully. An account with a
// passphrase gives up nothing until it is unlocked - not its name, not its
// fingerprint - which is the point of keeping everything in one keyed file. It
// is listed by its directory id and marked locked.
AccountInfo readInfo(const std::string& id, const fs::path& file, const std::string& passphrase = {})
{
    AccountInfo info;
    info.id = id;
    info.file = file;
    // One open, not two: unlocking an account database runs its key derivation,
    // which is deliberately expensive.
    std::unique_ptr<AccountDb> db;
    try {
        db = std::make_unique<AccountDb>(file, passphrase);
    } catch (const std::exception& error) {
        // Locked is one reason a database does not open; a build that cannot read
        // it at all is another, and the two look identical from here. Say which
        // one it was, or an account that is merely unreadable reads to the user
        // as an account they have forgotten the passphrase for.
        bazarish::log::info("account {} did not open: {}", id, error.what());
        info.encrypted = true;
        return info;
    }
    const nlohmann::json meta = nlohmann::json::parse(db->text("meta"));
    // The name is inside, so a locked account has none to give - which is what
    // the caller shows as "locked" rather than as a name it does not have.
    info.name = meta.value("name", std::string{});
    if (info.name.find_first_not_of(" \t\r\n") == std::string::npos) {
        info.name.clear();
    }
    info.fingerprint = meta.value("fingerprint", std::string{});
    info.encrypted = meta.value("encrypted", false);
    return info;
}

}  // namespace

fs::path AccountManager::globalRoot()
{
#ifdef _WIN32
    // The roaming application data directory, which is where a Windows user's
    // own data belongs and what the environment names.
    if (const char* const appData = std::getenv("APPDATA");
        appData != nullptr && appData[0] != '\0') {
        return fs::path(appData) / "Bazarish";
    }
    return fs::current_path() / "Bazarish";
#else
    const char* const home = std::getenv("HOME");
    const fs::path base = home != nullptr ? fs::path(home) : fs::current_path();
    return base / ".local" / "share" / "bazarish";
#endif
}

namespace {

// The directory the application lives in, which is where portable data goes.
// Read from the process itself rather than argv[0], which a caller can set to
// anything - except inside an AppImage, where the executable is on a read-only
// mount of its own and the file the user actually launched is the one named by
// APPIMAGE (set by the AppImage runtime).
fs::path executableDir()
{
#ifdef _WIN32
    // The module path is the only thing that names this process's own file.
    std::string path(MAX_PATH, '\0');
    const DWORD written = ::GetModuleFileNameA(nullptr, path.data(),
        static_cast<DWORD>(path.size()));
    if (written == 0 || written >= path.size()) {
        return fs::current_path();
    }
    path.resize(written);
    return fs::path(path).parent_path();
#else
    if (const char* const bundle = std::getenv("APPIMAGE");
        bundle != nullptr && bundle[0] != '\0') {
        return fs::path(bundle).parent_path();
    }
    std::error_code error;
    const fs::path self = fs::read_symlink("/proc/self/exe", error);
    return error ? fs::current_path() : self.parent_path();
#endif
}

}  // namespace

fs::path AccountManager::portableMarker()
{
    return executableDir() / ".bazarish.portable";
}

fs::path AccountManager::portableRoot()
{
    return executableDir() / "bazarish_data";
}

bool AccountManager::portable()
{
    std::error_code ignored;
    return fs::exists(portableMarker(), ignored);
}

fs::path AccountManager::dataRoot()
{
    return portable() ? portableRoot() : globalRoot();
}

fs::path AccountManager::defaultRoot()
{
    const fs::path accounts = dataRoot() / "accounts";
    // Accounts used to be called profiles, and the directory was named after
    // them. Renaming the word must not lose what is in it: an installation that
    // still has the old directory and none of the new one keeps its accounts,
    // moved once, here.
    std::error_code ec;
    const fs::path legacy = dataRoot() / "profiles";
    if (!fs::exists(accounts, ec) && fs::exists(legacy, ec)) {
        fs::rename(legacy, accounts, ec);
        if (ec) {
            bazarish::log::warn("accounts left in {}: {}", legacy.string(), ec.message());
            return legacy;
        }
        bazarish::log::info("accounts moved from {} to {}", legacy.string(), accounts.string());
    }
    return accounts;
}

AccountManager::AccountManager(fs::path root)
    : root_(std::move(root))
{
    fs::create_directories(root_);
}

std::map<std::string, std::string> AccountManager::adoptOpaqueNames()
{
    std::map<std::string, std::string> renamed;
    if (!fs::exists(root_)) {
        return renamed;
    }
    for (const fs::directory_entry& entry : fs::directory_iterator(root_)) {
        if (!entry.is_regular_file() || entry.path().extension() != kFileSuffix) {
            continue;
        }
        const std::string stem = entry.path().stem().string();
        if (isAccountId(stem)) {
            continue;
        }
        std::string fresh = newAccountId();
        while (exists(fresh)) {
            fresh = newAccountId();
        }
        // Nothing is open yet - this runs before any account is unlocked - so the
        // file and its key sidecar move together and the name is gone from the
        // directory for good.
        movePair(entry.path(), fileFor(fresh));
        renamed.emplace(stem, fresh);
        bazarish::log::info("an account file named after its account was renamed");
    }
    return renamed;
}

fs::path AccountManager::fileFor(const std::string& id) const
{
    return root_ / (id + kFileSuffix);
}

bool AccountManager::exists(const std::string& id) const
{
    return fs::exists(fileFor(id));
}

std::vector<AccountInfo> AccountManager::list() const
{
    std::vector<AccountInfo> accounts;
    if (!fs::exists(root_)) {
        return accounts;
    }
    for (const fs::directory_entry& entry : fs::directory_iterator(root_)) {
        if (!entry.is_regular_file() || entry.path().extension() != kFileSuffix) {
            continue;
        }
        accounts.push_back(readInfo(entry.path().stem().string(), entry.path()));
    }
    return accounts;
}

AccountInfo AccountManager::create(const std::string& name, const std::string& passphrase)
{
    if (name.find_first_not_of(" \t\r\n") == std::string::npos) {
        throw std::runtime_error("an account needs a name");
    }
    // The name travels: it is the label a contact request seeds the recipient's
    // address book with, and that request is the one thing a stranger may put in
    // a mailbox. Bounded here as well as where it is set, so an account cannot be
    // created with a name that would not fit.
    if (name.size() > kMaxAccountNameBytes) {
        throw std::runtime_error("an account name may be at most "
            + std::to_string(kMaxAccountNameBytes) + " bytes");
    }
    // No check for a name already in use: a locked account will not say what it
    // is called, so the only honest answer would come from opening every one of
    // them. Two accounts may share a name; they never share a file.
    std::string id = newAccountId();
    while (exists(id)) {
        id = newAccountId();
    }
    Session::create(fileFor(id), passphrase, name);
    return readInfo(id, fileFor(id), passphrase);
}

Session AccountManager::open(const std::string& id, const std::string& passphrase) const
{
    return Session::open(fileFor(id), passphrase);
}

AccountInfo AccountManager::import(const std::string& name, const fs::path& bundleFile,
    const std::string& password, const std::string& atRestPassphrase)
{
    // The display name is restored from the bundle (importAccount writes the bundled
    // meta verbatim). An explicit name, when given, only chooses the on-disk id;
    // when omitted the id is derived from the restored name. So import into a temp
    // dir first, read the restored name, then move it into place under its final id.
    const fs::path tmp = root_ / ".import-tmp.db";
    removePair(tmp);
    Session::importAccount(bundleFile, tmp, password, atRestPassphrase);
    const std::string restoredName = readInfo(std::string{}, tmp, atRestPassphrase).name;
    if ((name.empty() ? restoredName : name).find_first_not_of(" \t\r\n")
        == std::string::npos) {
        removePair(tmp);
        throw std::runtime_error("an account needs a name");
    }
    std::string id = newAccountId();
    while (exists(id)) {
        id = newAccountId();
    }
    movePair(tmp, fileFor(id));
    return readInfo(id, fileFor(id), atRestPassphrase);
}

void AccountManager::remove(const std::string& id)
{
    removePair(fileFor(id));
}

}  // namespace bazarish::client
