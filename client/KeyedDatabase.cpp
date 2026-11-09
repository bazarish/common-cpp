// Bazarish project (c) 2026
#include "KeyedDatabase.hpp"

#include <bazarish/PathText.hpp>

#include <sqlcipher/sqlite3.h>

#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

namespace bazarish::client {

namespace {

constexpr int kBusyTimeoutMs = 5000;
// sqlite3_backup_step's page count that means every page at once.
constexpr int kAllPages = -1;
// sqlite3_prepare_v2 reads the statement up to its terminating zero.
constexpr int kWholeStatement = -1;

struct BackupFinish {
    void operator()(sqlite3_backup* const backup) const
    {
        static_cast<void>(sqlite3_backup_finish(backup));
    }
};

}  // namespace

void SqliteClose::operator()(sqlite3* const db) const
{
    static_cast<void>(sqlite3_close(db));
}

void SqliteFinalize::operator()(sqlite3_stmt* const statement) const
{
    static_cast<void>(sqlite3_finalize(statement));
}

SqliteHandle openKeyed(const std::filesystem::path& file, const Bytes& key)
{
    sqlite3* opened = nullptr;
    // SQLite takes a UTF-8 file name, and hands back a handle to close even when it fails.
    const int status = sqlite3_open(utf8OfPath(file).c_str(), &opened);
    SqliteHandle db(opened);
    if (status != SQLITE_OK) {
        return nullptr;
    }
    static_cast<void>(
        sqlite3_exec(db.get(), "PRAGMA cipher_log_level = NONE", nullptr, nullptr, nullptr));
    const std::string pragma = "PRAGMA key = \"x'" + toHex(key) + "'\"";
    if (sqlite3_exec(db.get(), pragma.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
        return nullptr;
    }
    if (sqlite3_busy_timeout(db.get(), kBusyTimeoutMs) != SQLITE_OK) {
        return nullptr;
    }
    if (sqlite3_exec(db.get(), "SELECT count(*) FROM sqlite_master", nullptr, nullptr, nullptr)
        != SQLITE_OK) {
        return nullptr;
    }
    return db;
}

void copyKeyedDatabase(const std::filesystem::path& from, const std::filesystem::path& to,
    const Bytes& key)
{
    const SqliteHandle source = openKeyed(from, key);
    if (source == nullptr) {
        throw std::runtime_error("database copy: " + utf8OfPath(from) + " does not open");
    }
    std::error_code absent;
    std::filesystem::remove(to, absent);
    const SqliteHandle target = openKeyed(to, key);
    if (target == nullptr) {
        throw std::runtime_error("database copy: " + utf8OfPath(to) + " does not open");
    }
    std::unique_ptr<sqlite3_backup, BackupFinish> backup(
        sqlite3_backup_init(target.get(), "main", source.get(), "main"));
    if (backup == nullptr) {
        throw std::runtime_error(std::string("database copy: ") + sqlite3_errmsg(target.get()));
    }
    const int stepped = sqlite3_backup_step(backup.get(), kAllPages);
    const int finished = sqlite3_backup_finish(backup.release());
    if (stepped != SQLITE_DONE || finished != SQLITE_OK) {
        throw std::runtime_error(std::string("database copy: ") + sqlite3_errmsg(target.get()));
    }
}

Database::Database(SqliteHandle db, std::string label)
    : label_(std::move(label))
    , db_(std::move(db))
{
    if (db_ == nullptr) {
        throw std::invalid_argument(label_ + ": no database to work on");
    }
}

void Database::run(const std::string& sql) const
{
    char* message = nullptr;
    const int status = sqlite3_exec(db_.get(), sql.c_str(), nullptr, nullptr, &message);
    const std::unique_ptr<char, decltype(&sqlite3_free)> held(message, &sqlite3_free);
    if (status != SQLITE_OK) {
        throw std::runtime_error(label_ + ": " + (held == nullptr ? "unknown" : held.get()));
    }
}

std::int64_t Database::lastInsertId() const
{
    return sqlite3_last_insert_rowid(db_.get());
}

int Database::changes() const
{
    return sqlite3_changes(db_.get());
}

Statement::Statement(const Database& database, const std::string& sql)
    : label_(database.label())
{
    sqlite3_stmt* prepared = nullptr;
    const int status
        = sqlite3_prepare_v2(database.db_.get(), sql.c_str(), kWholeStatement, &prepared, nullptr);
    statement_.reset(prepared);
    if (status != SQLITE_OK) {
        throw std::runtime_error(
            label_ + ": cannot prepare a statement: " + sqlite3_errmsg(database.db_.get()));
    }
}

void Statement::bind(const int index, const std::string& text)
{
    if (sqlite3_bind_text(statement_.get(), index, text.data(), static_cast<int>(text.size()),
            SQLITE_TRANSIENT)
        != SQLITE_OK) {
        throw std::runtime_error(label_ + ": cannot bind a value");
    }
}

void Statement::bind(const int index, const std::int64_t value)
{
    if (sqlite3_bind_int64(statement_.get(), index, value) != SQLITE_OK) {
        throw std::runtime_error(label_ + ": cannot bind a value");
    }
}

void Statement::bind(const int index, const Bytes& blob)
{
    // A null pointer would bind NULL; an empty value is an empty blob.
    const int status = blob.empty()
        ? sqlite3_bind_zeroblob(statement_.get(), index, 0)
        : sqlite3_bind_blob64(statement_.get(), index, blob.data(), blob.size(), SQLITE_TRANSIENT);
    if (status != SQLITE_OK) {
        throw std::runtime_error(label_ + ": cannot bind a value");
    }
}

bool Statement::step()
{
    const int outcome = sqlite3_step(statement_.get());
    if (outcome == SQLITE_ROW) {
        return true;
    }
    if (outcome != SQLITE_DONE) {
        throw std::runtime_error(label_ + ": a statement did not complete");
    }
    return false;
}

std::string Statement::text(const int index) const
{
    const unsigned char* const value = sqlite3_column_text(statement_.get(), index);
    return value == nullptr ? std::string() : reinterpret_cast<const char*>(value);
}

std::int64_t Statement::number(const int index) const
{
    return sqlite3_column_int64(statement_.get(), index);
}

Bytes Statement::blob(const int index) const
{
    const auto* const data
        = static_cast<const unsigned char*>(sqlite3_column_blob(statement_.get(), index));
    const int size = sqlite3_column_bytes(statement_.get(), index);
    return data == nullptr ? Bytes() : Bytes(data, data + size);
}

}  // namespace bazarish::client
