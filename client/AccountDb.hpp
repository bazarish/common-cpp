// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <filesystem>
#include <optional>
#include <string>

struct sqlite3;

namespace bazarish::client {

class AccountDb {
public:
    // Opens (creating it when absent) the database at `file`.
    AccountDb(const std::filesystem::path& file, const std::string& passphrase);
    ~AccountDb();

    AccountDb(const AccountDb&) = delete;
    AccountDb& operator=(const AccountDb&) = delete;

    static bool opens(const std::filesystem::path& file, const std::string& passphrase);

    std::optional<Bytes> get(const std::string& name) const;
    std::string text(const std::string& name) const;
    void put(const std::string& name, const Bytes& value);
    void putText(const std::string& name, const std::string& value);
    void erase(const std::string& name);
    bool has(const std::string& name) const;

    void rekey(const std::string& passphrase);

private:
    std::filesystem::path file_;
    sqlite3* db_ = nullptr;
};

}  // namespace bazarish::client
