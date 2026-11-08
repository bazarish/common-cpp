// Bazarish project (c) 2026
#include "AccountDb.hpp"

#include "AccountKey.hpp"
#include "KeyedDatabase.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/PathText.hpp>

#include <stdexcept>

namespace bazarish::client {

namespace {

namespace fs = std::filesystem;

SqliteHandle opened(const fs::path& file, const std::string& passphrase)
{
    if (file.has_parent_path()) {
        fs::create_directories(file.parent_path());
    }
    SqliteHandle db = openKeyed(file, accountkey::keyFor(file, passphrase));
    if (db == nullptr) {
        throw std::runtime_error("account database: " + file.string() + " is unreadable");
    }
    return db;
}

}  // namespace

AccountDb::AccountDb(const fs::path& file, const std::string& passphrase)
    : file_(file)
    , db_(opened(file, passphrase), "account database")
{
    db_.run("CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, value BLOB)");
}

std::optional<Bytes> AccountDb::get(const std::string& name) const
{
    Statement statement(db_, "SELECT value FROM state WHERE name = ?");
    statement.bind(1, name);
    if (!statement.step()) {
        return std::nullopt;
    }
    return statement.blob(0);
}

std::string AccountDb::text(const std::string& name) const
{
    const std::optional<Bytes> value = get(name);
    return value.has_value() ? std::string(value->begin(), value->end()) : std::string();
}

void AccountDb::put(const std::string& name, const Bytes& value)
{
    Statement statement(db_, "INSERT OR REPLACE INTO state (name, value) VALUES (?, ?)");
    statement.bind(1, name);
    statement.bind(2, value);
    static_cast<void>(statement.step());
}

void AccountDb::putText(const std::string& name, const std::string& value)
{
    put(name, Bytes(value.begin(), value.end()));
}

void AccountDb::erase(const std::string& name)
{
    Statement statement(db_, "DELETE FROM state WHERE name = ?");
    statement.bind(1, name);
    static_cast<void>(statement.step());
}

bool AccountDb::has(const std::string& name) const
{
    return get(name).has_value();
}

void AccountDb::rekey(const std::string& passphrase)
{
    accountkey::rewrap(file_, passphrase);
}

}  // namespace bazarish::client
