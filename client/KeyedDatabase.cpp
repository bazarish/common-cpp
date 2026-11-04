// Bazarish project (c) 2026
#include "KeyedDatabase.hpp"

#include <bazarish/PathText.hpp>

#include <sqlcipher/sqlite3.h>

#include <stdexcept>
#include <string>
#include <system_error>

namespace bazarish::client {

namespace {

constexpr int kBusyTimeoutMs = 5000;
// sqlite3_backup_step's page count that means every page at once.
constexpr int kAllPages = -1;

}  // namespace

sqlite3* openKeyed(const std::filesystem::path& file, const Bytes& key)
{
    sqlite3* db = nullptr;
    // SQLite takes a UTF-8 file name.
    if (sqlite3_open(utf8OfPath(file).c_str(), &db) != SQLITE_OK) {
        sqlite3_close(db);
        return nullptr;
    }
    sqlite3_exec(db, "PRAGMA cipher_log_level = NONE", nullptr, nullptr, nullptr);
    const std::string pragma = "PRAGMA key = \"x'" + toHex(key) + "'\"";
    if (sqlite3_exec(db, pragma.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return nullptr;
    }
    sqlite3_busy_timeout(db, kBusyTimeoutMs);
    if (sqlite3_exec(db, "SELECT count(*) FROM sqlite_master", nullptr, nullptr, nullptr)
        != SQLITE_OK) {
        sqlite3_close(db);
        return nullptr;
    }
    return db;
}

void copyKeyedDatabase(const std::filesystem::path& from, const std::filesystem::path& to,
    const Bytes& key)
{
    sqlite3* const source = openKeyed(from, key);
    if (source == nullptr) {
        throw std::runtime_error("database copy: " + from.string() + " does not open");
    }
    std::error_code absent;
    std::filesystem::remove(to, absent);
    sqlite3* const target = openKeyed(to, key);
    if (target == nullptr) {
        sqlite3_close(source);
        throw std::runtime_error("database copy: " + to.string() + " does not open");
    }
    sqlite3_backup* const backup = sqlite3_backup_init(target, "main", source, "main");
    const int stepped = backup == nullptr ? sqlite3_errcode(target) : sqlite3_backup_step(backup, kAllPages);
    const int finished = backup == nullptr ? SQLITE_OK : sqlite3_backup_finish(backup);
    const std::string reason = sqlite3_errmsg(target);
    sqlite3_close(target);
    sqlite3_close(source);
    if (stepped != SQLITE_DONE || finished != SQLITE_OK) {
        throw std::runtime_error("database copy: " + reason);
    }
}

}  // namespace bazarish::client
