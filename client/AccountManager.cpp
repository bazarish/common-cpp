// Bazarish project (c) 2026
#include "AccountManager.hpp"

#include "AccountDb.hpp"
#include "AccountKey.hpp"

#include <bazarish/Limits.hpp>
#include <bazarish/PrivateFile.hpp>

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

constexpr const char* kFileSuffix = ".db";

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

constexpr std::size_t kAccountIdBytes = 8;

std::string newAccountId()
{
    return toHex(randomBytes(kAccountIdBytes));
}

AccountInfo readInfo(const std::string& id, const fs::path& file, const std::string& passphrase = {})
{
    AccountInfo info;
    info.id = id;
    info.file = file;
    std::unique_ptr<AccountDb> db;
    try {
        db = std::make_unique<AccountDb>(file, passphrase);
    } catch (const std::exception& error) {
        bazarish::log::info("account {} did not open: {}", id, error.what());
        info.encrypted = true;
        return info;
    }
    const nlohmann::json meta = nlohmann::json::parse(db->text("meta"));
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

fs::path executableDir()
{
#ifdef _WIN32
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
    if (name.size() > kMaxAccountNameBytes) {
        throw std::runtime_error("an account name may be at most "
            + std::to_string(kMaxAccountNameBytes) + " bytes");
    }
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

AccountInfo AccountManager::import(const std::string& name, const Bytes& bundle,
    const std::string& password, const std::string& atRestPassphrase)
{
    const fs::path tmp = root_ / ".import-tmp.db";
    removePair(tmp);
    std::string id;
    try {
        Session::importAccountBytes(bundle, tmp, password, atRestPassphrase);
        const std::string restoredName = readInfo(std::string{}, tmp, atRestPassphrase).name;
        if ((name.empty() ? restoredName : name).find_first_not_of(" \t\r\n")
            == std::string::npos) {
            throw std::runtime_error("an account needs a name");
        }
        id = newAccountId();
        while (exists(id)) {
            id = newAccountId();
        }
    } catch (...) {
        removePair(tmp);
        throw;
    }
    movePair(tmp, fileFor(id));
    return readInfo(id, fileFor(id), atRestPassphrase);
}

AccountInfo AccountManager::import(const std::string& name, const fs::path& bundleFile,
    const std::string& password, const std::string& atRestPassphrase)
{
    const std::string sealed = readFileText(bundleFile);
    return import(name, Bytes(sealed.begin(), sealed.end()), password, atRestPassphrase);
}

void AccountManager::remove(const std::string& id)
{
    removePair(fileFor(id));
}

}  // namespace bazarish::client
