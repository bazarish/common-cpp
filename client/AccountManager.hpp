// Bazarish project (c) 2026
#pragma once

#include "Session.hpp"

#include <filesystem>
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

    std::vector<AccountInfo> list() const;
    bool exists(const std::string& id) const;
    std::filesystem::path fileFor(const std::string& id) const;

    AccountInfo create(const std::string& name, const std::string& passphrase = {});
    Session open(const std::string& id, const std::string& passphrase = {}) const;
    AccountInfo import(const std::string& name, const std::filesystem::path& bundleFile,
        const std::string& password, const std::string& atRestPassphrase = {});
    void remove(const std::string& id);

private:
    std::filesystem::path root_;
};

}  // namespace bazarish::client
