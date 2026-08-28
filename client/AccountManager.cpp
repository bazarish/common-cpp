// Bazarish project (c) 2026
#include "AccountManager.hpp"

#include "AccountDb.hpp"
#include "AccountKey.hpp"

#include <memory>

#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include <cstdlib>
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

// An account is stored under its own name, so the name has to survive as a file
// name. Only what a file system refuses is replaced - the reserved characters of
// Windows and macOS included, so a portable copy on a stick stays readable - and
// everything else, Unicode included, is kept as the user typed it.
std::string sanitizeFileName(const std::string& name)
{
    static const std::string reserved = "/\\:*?\"<>|";
    std::string out;
    for (const char c : name) {
        const bool control = static_cast<unsigned char>(c) < 0x20;
        out.push_back(control || reserved.find(c) != std::string::npos ? '_' : c);
    }
    // Leading dots hide the file; trailing dots and spaces are dropped by Windows.
    const std::size_t first = out.find_first_not_of('.');
    out = first == std::string::npos ? std::string() : out.substr(first);
    while (!out.empty() && (out.back() == '.' || out.back() == ' ')) {
        out.pop_back();
    }
    return out;
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
    info.name = id;
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
    // For an account in place the name and the file name are the same string; an
    // imported bundle is read before it has a file name of its own, and there the
    // name inside is all there is.
    info.name = meta.value("name", id);
    info.fingerprint = meta.value("fingerprint", std::string{});
    info.encrypted = meta.value("encrypted", false);
    info.connected = !meta.at("endpoint").value("facades", nlohmann::json::array()).empty();
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
    if (const char* const xdg = std::getenv("XDG_DATA_HOME"); xdg != nullptr && xdg[0] != '\0') {
        return fs::path(xdg) / "bazarish";
    }
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

fs::path AccountManager::fileFor(const std::string& id) const
{
    return root_ / (sanitizeFileName(id) + kFileSuffix);
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
    const std::string id = sanitizeFileName(name);
    if (id.empty()) {
        throw std::runtime_error("an account needs a name");
    }
    if (exists(id)) {
        throw std::runtime_error("an account with this name already exists");
    }
    Session::create(fileFor(id), passphrase, id);
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
    const std::string id = sanitizeFileName(name.empty() ? restoredName : name);
    if (id.empty() || exists(id)) {
        removePair(tmp);
        throw std::runtime_error(id.empty() ? "an account needs a name"
                                            : "an account with this name already exists");
    }
    movePair(tmp, fileFor(id));
    return readInfo(id, fileFor(id), atRestPassphrase);
}

void AccountManager::remove(const std::string& id)
{
    removePair(fileFor(id));
}

}  // namespace bazarish::client
