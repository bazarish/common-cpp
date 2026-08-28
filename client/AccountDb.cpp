// Bazarish project (c) 2026
#include "AccountDb.hpp"

#include "AccountKey.hpp"

#include <bazarish/Bytes.hpp>

#include <sqlcipher/sqlite3.h>

#include <stdexcept>

namespace bazarish::client {

namespace {

namespace fs = std::filesystem;

// How long a writer waits for another connection to finish before giving up. The
// transcript and this store are two connections on one file, so a write can meet
// a lock; they are both in-process and short, so the wait is a formality.
constexpr int kBusyTimeoutMs = 5000;

// The database is opened with a raw key, so SQLCipher derives nothing: the
// passphrase guards the key file beside it, and that is where the expensive
// derivation lives (see AccountKey).

// A raw key is given to SQLCipher as hex in a blob literal: x'<64 hex chars>'.
std::string rawKeyLiteral(const Bytes& key)
{
    return "x'" + toHex(key) + "'";
}

void run(sqlite3* const db, const std::string& sql)
{
    char* message = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &message) != SQLITE_OK) {
        const std::string reason = message == nullptr ? "unknown error" : message;
        sqlite3_free(message);
        throw std::runtime_error("account database: " + reason);
    }
}

// Opens the file and unlocks it. The key pragma has to be the first statement on
// the connection.
sqlite3* openKeyed(const fs::path& file, const Bytes& key)
{
    sqlite3* db = nullptr;
    if (sqlite3_open(file.string().c_str(), &db) != SQLITE_OK) {
        sqlite3_close(db);
        return nullptr;
    }
    // SQLCipher reports a failed decryption on stderr; callers report it through
    // their own return values instead.
    sqlite3_exec(db, "PRAGMA cipher_log_level = NONE", nullptr, nullptr, nullptr);
    const std::string pragma = "PRAGMA key = \"" + rawKeyLiteral(key) + "\"";
    if (sqlite3_exec(db, pragma.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return nullptr;
    }
    sqlite3_busy_timeout(db, kBusyTimeoutMs);
    // With the wrong key the pages do not decrypt and the first read fails.
    if (sqlite3_exec(db, "SELECT count(*) FROM sqlite_master", nullptr, nullptr, nullptr)
        != SQLITE_OK) {
        sqlite3_close(db);
        return nullptr;
    }
    return db;
}




}  // namespace

AccountDb::AccountDb(const fs::path& file, const std::string& passphrase)
    : file_(file)
{
    if (file.has_parent_path()) {
        fs::create_directories(file.parent_path());
    }
    // Unwrapping the key is where a wrong passphrase is caught; this throws.
    db_ = openKeyed(file, accountkey::keyFor(file, passphrase));
    if (db_ == nullptr) {
        throw std::runtime_error("account database: " + file.string() + " is unreadable");
    }
    run(db_, "CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, value BLOB)");
}

AccountDb::~AccountDb()
{
    sqlite3_close(db_);
}

bool AccountDb::opens(const fs::path& file, const std::string& passphrase)
{
    return fs::exists(file) && accountkey::unlocks(file, passphrase);
}

std::optional<Bytes> AccountDb::get(const std::string& name) const
{
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT value FROM state WHERE name = ?", -1, &statement, nullptr)
        != SQLITE_OK) {
        throw std::runtime_error(std::string("account database: ") + sqlite3_errmsg(db_));
    }
    sqlite3_bind_text(statement, 1, name.c_str(), static_cast<int>(name.size()), SQLITE_TRANSIENT);
    std::optional<Bytes> value;
    if (sqlite3_step(statement) == SQLITE_ROW) {
        const auto* const data = static_cast<const unsigned char*>(sqlite3_column_blob(statement, 0));
        const int size = sqlite3_column_bytes(statement, 0);
        value = Bytes(data, data + size);
    }
    sqlite3_finalize(statement);
    return value;
}

std::string AccountDb::text(const std::string& name) const
{
    const std::optional<Bytes> value = get(name);
    return value.has_value() ? std::string(value->begin(), value->end()) : std::string();
}

void AccountDb::put(const std::string& name, const Bytes& value)
{
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db_,
            // Not an UPSERT: it arrived in SQLite 3.24, and the SQLCipher some
            // distributions ship is older. The table is a key and its value, so
            // replacing the row says exactly the same thing.
            "INSERT OR REPLACE INTO state (name, value) VALUES (?, ?)",
            -1, &statement, nullptr)
        != SQLITE_OK) {
        throw std::runtime_error(std::string("account database: ") + sqlite3_errmsg(db_));
    }
    sqlite3_bind_text(statement, 1, name.c_str(), static_cast<int>(name.size()), SQLITE_TRANSIENT);
    // A zero-length blob still needs a non-null pointer.
    const unsigned char empty = 0;
    sqlite3_bind_blob(statement, 2, value.empty() ? &empty : value.data(),
        static_cast<int>(value.size()), SQLITE_TRANSIENT);
    const int status = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (status != SQLITE_DONE) {
        throw std::runtime_error(std::string("account database: ") + sqlite3_errmsg(db_));
    }
}

void AccountDb::putText(const std::string& name, const std::string& value)
{
    put(name, Bytes(value.begin(), value.end()));
}

void AccountDb::erase(const std::string& name)
{
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM state WHERE name = ?", -1, &statement, nullptr)
        != SQLITE_OK) {
        throw std::runtime_error(std::string("account database: ") + sqlite3_errmsg(db_));
    }
    sqlite3_bind_text(statement, 1, name.c_str(), static_cast<int>(name.size()), SQLITE_TRANSIENT);
    const int status = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (status != SQLITE_DONE) {
        throw std::runtime_error(std::string("account database: ") + sqlite3_errmsg(db_));
    }
}

bool AccountDb::has(const std::string& name) const
{
    return get(name).has_value();
}

void AccountDb::rekey(const std::string& passphrase)
{
    // Only the hundred bytes beside the database change: the database key stays
    // what it was, so not a page of it is rewritten.
    accountkey::rewrap(file_, passphrase);
}

}  // namespace bazarish::client
