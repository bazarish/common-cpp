// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

struct sqlite3;
struct sqlite3_stmt;

namespace bazarish::client {

struct SqliteClose {
    void operator()(sqlite3* db) const;
};
struct SqliteFinalize {
    void operator()(sqlite3_stmt* statement) const;
};
using SqliteHandle = std::unique_ptr<sqlite3, SqliteClose>;
using StatementHandle = std::unique_ptr<sqlite3_stmt, SqliteFinalize>;

// Null when the file cannot be opened or the key does not read it.
SqliteHandle openKeyed(const std::filesystem::path& file, const Bytes& key);

// A whole copy under the same key while other connections keep writing to the source.
void copyKeyedDatabase(
    const std::filesystem::path& from, const std::filesystem::path& to, const Bytes& key);

// One connection; whatever goes wrong in it is thrown with the label in front.
class Database {
public:
    Database(SqliteHandle db, std::string label);

    const std::string& label() const { return label_; }
    void run(const std::string& sql) const;
    std::int64_t lastInsertId() const;
    int changes() const;

private:
    friend class Statement;

    std::string label_;
    SqliteHandle db_;
};

class Statement {
public:
    Statement(const Database& database, const std::string& sql);

    void bind(int index, const std::string& text);
    void bind(int index, std::int64_t value);
    void bind(int index, const Bytes& blob);
    bool step();
    std::string text(int index) const;
    std::int64_t number(int index) const;
    Bytes blob(int index) const;

private:
    std::string label_;
    StatementHandle statement_;
};

}  // namespace bazarish::client
