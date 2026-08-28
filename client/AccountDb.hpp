// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <filesystem>
#include <optional>
#include <string>

// The SQLCipher connection handle, opaque here.
struct sqlite3;

namespace bazarish::client {

// An account's storage: one encrypted SQLite (SQLCipher) file holding everything
// the account is - keys, metadata, contacts, blobs and the message transcript.
// The file is the account: it lives in the accounts directory under the account's
// own name, and without its key it gives up nothing but that name.
//
// This class owns the small named values; the transcript owns its own tables on
// the same file through its own connection.
class AccountDb {
public:
    // Opens (creating it when absent) the database at `file`. The database key is
    // a random 32 bytes kept in "<file>.key" beside it, sealed under `passphrase`;
    // opening throws when the passphrase does not unseal it - a wrong passphrase
    // must not read as an empty account.
    AccountDb(const std::filesystem::path& file, const std::string& passphrase);
    ~AccountDb();

    AccountDb(const AccountDb&) = delete;
    AccountDb& operator=(const AccountDb&) = delete;

    // Whether the key opens this database. Used to tell a locked account from an
    // unlocked one without throwing.
    static bool opens(const std::filesystem::path& file, const std::string& passphrase);

    std::optional<Bytes> get(const std::string& name) const;
    std::string text(const std::string& name) const;  // empty when absent
    void put(const std::string& name, const Bytes& value);
    void putText(const std::string& name, const std::string& value);
    void erase(const std::string& name);
    bool has(const std::string& name) const;

    // Seals the same database key under a new passphrase. Rewrites the key file
    // beside the database; the database itself is not touched.
    void rekey(const std::string& passphrase);

private:
    std::filesystem::path file_;
    sqlite3* db_ = nullptr;
};

}  // namespace bazarish::client
