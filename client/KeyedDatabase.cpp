// Bazarish project (c) 2026
#include "KeyedDatabase.hpp"

#include <bazarish/PathText.hpp>

#include <sqlcipher/sqlite3.h>

#include <string>

namespace bazarish::client {

namespace {

constexpr int kBusyTimeoutMs = 5000;

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

}  // namespace bazarish::client
