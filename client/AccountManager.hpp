// Bazarish project (c) 2026
#pragma once

#include "Session.hpp"

#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace bazarish::client {

// Summary of an account on disk. An account with a passphrase gives up nothing
// beyond its name until it is unlocked - the name is what the file is called.
struct AccountInfo {
    // Stable identifier = the account name, which is also the file name.
    std::string id;
    // Human display label set at creation; the same string as the id.
    std::string name;
    std::filesystem::path file;
    std::string fingerprint;
    bool encrypted = false;
};

// Manages the set of local accounts under a root directory. An account is one
// file there, "<name>.db", named after the account itself. Enumerates, creates,
// opens and removes them.
class AccountManager {
public:
    // Where this installation keeps everything: accounts, the I2P router's state,
    // the global settings. Normally the user's data directory; when a file named
    // ".bazarish.portable" sits beside the executable, a "bazarish_data" folder
    // beside it instead, so a copy on a stick carries its own data.
    static std::filesystem::path dataRoot();
    // Whether this installation is running portable (the marker file is present).
    static bool portable();
    // The marker itself, and the portable data folder - so a caller can move
    // between the two modes.
    static std::filesystem::path portableMarker();
    static std::filesystem::path portableRoot();
    static std::filesystem::path globalRoot();

    static std::filesystem::path defaultRoot();

    explicit AccountManager(std::filesystem::path root);

    // Renames any account file still named after its account, and answers what
    // moved where (old id -> new). A directory listing is readable without any
    // passphrase, so a file named after the account hands over the roster; this
    // catches what an earlier build left behind. Call it before anything is
    // opened - it moves files.
    std::map<std::string, std::string> adoptOpaqueNames();

    std::vector<AccountInfo> list() const;
    bool exists(const std::string& id) const;
    // Where an account of this name lives. The name carries into the file name as
    // it is, Unicode included; only what a file system cannot take is replaced.
    std::filesystem::path fileFor(const std::string& id) const;

    // Creates a new account under this name. Throws if one already exists.
    AccountInfo create(const std::string& name, const std::string& passphrase = {});
    // Opens an existing account; the passphrase is required when encrypted.
    Session open(const std::string& id, const std::string& passphrase = {}) const;
    // Imports an exported bundle as a new account under the given name.
    AccountInfo import(const std::string& name, const std::filesystem::path& bundleFile,
        const std::string& password, const std::string& atRestPassphrase = {});
    void remove(const std::string& id);

private:
    std::filesystem::path root_;
};

}  // namespace bazarish::client
