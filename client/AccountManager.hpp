// Bazarish project (c) 2026
#pragma once

#include "Session.hpp"

#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish::client {

struct AccountInfo {
    std::string id;
    std::string name;
    std::filesystem::path file;
    std::string fingerprint;
    bool encrypted = false;
};

class AccountManager {
public:
    static std::filesystem::path dataRoot();
    static bool portable();
    static std::filesystem::path portableMarker();
    static std::filesystem::path portableRoot();
    static std::filesystem::path globalRoot();

    static std::filesystem::path defaultRoot();

    explicit AccountManager(std::filesystem::path root);
    // Called once, before any import.
    void discardInterruptedImports();

    std::vector<AccountInfo> list() const;
    bool exists(const std::string& id) const;
    std::filesystem::path fileFor(const std::string& id) const;

    AccountInfo create(
        const std::string& name, AccountKind kind, const std::string& passphrase = {});
    std::unique_ptr<Session> open(const std::string& id, const std::string& passphrase = {}) const;
    AccountInfo importBundle(
        const std::string& name, const Bytes& plain, const std::string& atRestPassphrase);
    AccountInfo import(const std::string& name, const Bytes& bundle,
        const std::string& password, const std::string& atRestPassphrase = {});
    AccountInfo import(const std::string& name, const std::filesystem::path& bundleFile,
        const std::string& password, const std::string& atRestPassphrase = {});
    void remove(const std::string& id);

private:
    std::filesystem::path root_;
    AccountInfo importWith(const std::string& name, const std::string& atRestPassphrase,
        const std::function<void(const std::filesystem::path&)>& write);

    std::mutex importMutex_;
};

}  // namespace bazarish::client
