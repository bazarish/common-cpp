// Bazarish project (c) 2026
#include "TranscriptDb.hpp"

#include "AccountKey.hpp"
#include "KeyedDatabase.hpp"
#include "MediaKeys.hpp"
#include "MessageTypes.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <sqlcipher/sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <stdexcept>
#include <system_error>
#include <thread>

namespace bazarish::client {

namespace {

namespace fs = std::filesystem;


// What people wrote and sent; never a service note.
constexpr std::array<const char*, 4> kExpiringTypes{kTypeText, kTypeImage, kTypeAudio, kTypeFile};

// SQLite reads every index entry for a DISTINCT; this seeks once per chat.
const std::string kEachPeer
    = "WITH RECURSIVE walk(peer) AS (SELECT MIN(peer) FROM messages UNION ALL"
      " SELECT (SELECT MIN(peer) FROM messages WHERE peer > walk.peer) FROM walk"
      " WHERE walk.peer IS NOT NULL), peers(peer) AS (SELECT peer FROM walk WHERE peer IS NOT NULL)";

bool expires(const std::string& type)
{
    return std::find(kExpiringTypes.begin(), kExpiringTypes.end(), type) != kExpiringTypes.end();
}

std::string expiringTypesSql()
{
    std::string quoted;
    for (const char* const type : kExpiringTypes) {
        quoted += (quoted.empty() ? "'" : ",'") + std::string(type) + "'";
    }
    return quoted;
}

class Query {
public:
    explicit Query(const SqliteHandle& db)
        : db_(*db)
    {
    }

    bool prepare(const std::string& sql)
    {
        stmt_.reset();
        bound_ = 0;
        sqlite3_stmt* prepared = nullptr;
        const int status = sqlite3_prepare_v2(
            &db_, sql.c_str(), static_cast<int>(sql.size()), &prepared, nullptr);
        stmt_.reset(prepared);
        if (status != SQLITE_OK) {
            log::warn("transcript: {}", sqlite3_errmsg(&db_));
            return false;
        }
        return true;
    }

    void bind(const std::string& value)
    {
        sqlite3_bind_text(
            stmt_.get(), ++bound_, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
    }
    void bind(const char* const value) { bind(std::string(value)); }
    void bind(const std::int64_t value) { sqlite3_bind_int64(stmt_.get(), ++bound_, value); }
    void bind(const Bytes& value)
    {
        sqlite3_bind_blob(
            stmt_.get(), ++bound_, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
    }
    void bind(const int value) { sqlite3_bind_int(stmt_.get(), ++bound_, value); }

    bool exec()
    {
        const int status = sqlite3_step(stmt_.get());
        if (status != SQLITE_DONE && status != SQLITE_ROW) {
            log::warn("transcript: {}", sqlite3_errmsg(&db_));
            return false;
        }
        changes_ = sqlite3_changes(&db_);
        stepped_ = status == SQLITE_ROW;
        return true;
    }

    bool exec(const std::string& sql) { return prepare(sql) && exec(); }

    bool next()
    {
        if (stepped_) {
            stepped_ = false;
            return true;
        }
        return sqlite3_step(stmt_.get()) == SQLITE_ROW;
    }

    std::string text(const int column) const
    {
        const unsigned char* const value = sqlite3_column_text(stmt_.get(), column);
        return value == nullptr ? std::string() : std::string(reinterpret_cast<const char*>(value));
    }
    std::int64_t number(const int column) const { return sqlite3_column_int64(stmt_.get(), column); }
    bool flag(const int column) const { return sqlite3_column_int(stmt_.get(), column) != 0; }
    bool isNull(const int column) const
    {
        return sqlite3_column_type(stmt_.get(), column) == SQLITE_NULL;
    }
    Bytes blob(const int column) const
    {
        const auto* const value = static_cast<const std::uint8_t*>(sqlite3_column_blob(stmt_.get(), column));
        const int size = sqlite3_column_bytes(stmt_.get(), column);
        return value == nullptr ? Bytes() : Bytes(value, value + size);
    }

    std::int64_t lastInsertId() const { return sqlite3_last_insert_rowid(&db_); }
    int changes() const { return changes_; }

private:
    sqlite3& db_;
    StatementHandle stmt_;
    int bound_ = 0;
    int changes_ = 0;
    bool stepped_ = false;
};

class Transaction {
public:
    explicit Transaction(const SqliteHandle& db)
        : db_(db)
    {
        Query begin(db_);
        begun_ = begin.exec("BEGIN IMMEDIATE");
    }
    ~Transaction()
    {
        if (!begun_ || committed_) {
            return;
        }
        Query rollback(db_);
        if (!rollback.exec("ROLLBACK")) {
            log::warn("transcript: a change could not be rolled back");
        }
    }

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    bool begun() const { return begun_; }

    bool commit()
    {
        Query end(db_);
        committed_ = end.exec("COMMIT");
        return committed_;
    }

private:
    const SqliteHandle& db_;
    bool begun_ = false;
    bool committed_ = false;
};

const std::string kMessageColumns = "id, peer, outgoing, type, e2eId, text, attName,"
                                    " attMime, attSize, attRef, attSrcPath, keyboard,"
                                    " edited, ts, status, orderKey, savedPath, replyTo,"
                                    " hasPicture, attDurationMs, attWave, forwarded, device,"
                                    " (SELECT author FROM group_posts g"
                                    " WHERE g.peer = messages.peer AND g.e2eId = messages.e2eId),"
                                    " (SELECT contactable FROM group_posts g"
                                    " WHERE g.peer = messages.peer AND g.e2eId = messages.e2eId),"
                                    " EXISTS (SELECT 1 FROM group_mentions n WHERE n.id = messages.id)";

void sortByOrder(std::vector<StoredMessage>& rows)
{
    std::sort(rows.begin(), rows.end(), [](const StoredMessage& a, const StoredMessage& b) {
        if (a.orderKey != b.orderKey) {
            return a.orderKey < b.orderKey;
        }
        return a.id < b.id;
    });
}

StoredMessage readMessageRow(const Query& query)
{
    StoredMessage m;
    m.id = query.number(0);
    m.peer = query.text(1);
    m.outgoing = query.flag(2);
    m.type = query.text(3);
    m.e2eId = query.text(4);
    m.text = query.text(5);
    m.attName = query.text(6);
    m.attMime = query.text(7);
    m.attSize = query.number(8);
    m.attRef = query.text(9);
    m.attSrcPath = query.text(10);
    m.keyboard = query.text(11);
    m.edited = query.flag(12);
    m.ts = query.number(13);
    m.status = static_cast<int>(query.number(14));
    m.orderKey = query.number(15);
    m.savedPath = query.text(16);
    m.replyTo = query.text(17);
    m.hasPicture = query.flag(18);
    m.attDurationMs = query.number(19);
    m.attWave = query.text(20);
    m.forwarded = query.flag(21);
    m.device = query.text(22);
    m.author = query.text(23);
    m.contactable = query.flag(24);
    m.fromHost = !query.isNull(23) && m.author.empty();
    m.mentionsMe = query.flag(25);
    return m;
}

std::vector<StoredMessage> readMessageRows(Query& query)
{
    std::vector<StoredMessage> rows;
    if (!query.exec()) {
        return rows;
    }
    while (query.next()) {
        rows.push_back(readMessageRow(query));
    }
    sortByOrder(rows);
    return rows;
}

StoredMessage readOneMessage(Query& query)
{
    if (!query.exec() || !query.next()) {
        return {};
    }
    return readMessageRow(query);
}

std::int64_t readNumber(Query& query)
{
    if (!query.exec() || !query.next()) {
        return 0;
    }
    return query.number(0);
}

// One process writes while another reads, and a reader must never hold the writer up.
bool takesWriteAheadLog(const SqliteHandle& db)
{
    Query journal(db);
    return journal.exec("PRAGMA journal_mode = WAL") && journal.text(0) == "wal";
}

bool zeroesDeleted(const SqliteHandle& db)
{
    Query secure(db);
    return secure.exec("PRAGMA secure_delete = ON") && secure.text(0) == "1";
}

std::uintmax_t sizeOrZero(const fs::path& file)
{
    std::error_code missing;
    const std::uintmax_t size = fs::file_size(file, missing);
    return missing ? 0 : size;
}

constexpr int kFixedColumnBytes = 32;
// PRAGMA auto_vacuum reads 2 for INCREMENTAL.
constexpr std::int64_t kIncrementalVacuum = 2;
// One step is one short write lock; 256 pages of 4 KiB are 1 MiB.
constexpr int kPagesPerStep = 256;
const std::string kVacuumStep = "PRAGMA incremental_vacuum(" + std::to_string(kPagesPerStep) + ")";
constexpr std::int64_t kUnknownCount = -1;

bool vacuumsIncrementally(const SqliteHandle& db)
{
    Query mode(db);
    return mode.exec("PRAGMA auto_vacuum") && mode.number(0) == kIncrementalVacuum;
}

std::string messageBytesExpression()
{
    std::string sum;
    for (const char* const column : {"text", "keyboard", "attWave", "attName", "attMime",
             "attRef", "attSrcPath", "savedPath", "replyTo", "e2eId", "type", "peer"}) {
        sum += "LENGTH(CAST(COALESCE(m." + std::string(column) + ",'') AS BLOB)) + ";
    }
    return sum + std::to_string(kFixedColumnBytes);
}

std::string keptMediaRows()
{
    std::string rows;
    for (const std::string prefix : {kPictureKeyPrefix, kVoiceKeyPrefix, kFileKeyPrefix}) {
        rows += (rows.empty() ? "" : " UNION ALL ") + std::string("SELECT substr(name, ")
            + std::to_string(prefix.size() + 1) + ") AS e2eId, LENGTH(value) AS bytes"
            + " FROM state WHERE name GLOB '" + prefix + "*'";
    }
    return rows;
}

std::string mediaOfRows(const std::string& rowCondition)
{
    return std::string("DELETE FROM state WHERE name IN (SELECT '") + kPictureKeyPrefix
        + "' || e2eId FROM messages WHERE e2eId != '' AND (" + rowCondition
        + ") UNION ALL SELECT '" + kVoiceKeyPrefix
        + "' || e2eId FROM messages WHERE e2eId != '' AND (" + rowCondition
        + ") UNION ALL SELECT '" + kFileKeyPrefix
        + "' || e2eId FROM messages WHERE e2eId != '' AND (" + rowCondition + "))";
}

}  // namespace

TranscriptReader::TranscriptReader() = default;

TranscriptReader::~TranscriptReader()
{
    close();
}

void TranscriptReader::close()
{
    db_.reset();
    path_.clear();
}

bool TranscriptReader::open(const fs::path& file, const SecretBytes& key)
{
    db_ = openKeyed(file, key);
    if (db_ == nullptr) {
        return false;
    }
    path_ = file;
    return true;
}

bool TranscriptStore::open(const fs::path& file, const std::string& passphrase)
{
    SecretBytes key;
    try {
        key = accountkey::keyFor(file, passphrase);
    } catch (const std::exception& error) {
        log::warn("transcript: {}", error.what());
        return false;
    }
    if (!TranscriptReader::open(file, key)) {
        return false;
    }
    if (!takesWriteAheadLog(db_)) {
        log::warn("transcript: the database did not take a write-ahead log");
        close();
        return false;
    }
    if (!zeroesDeleted(db_)) {
        log::warn("transcript: the database does not overwrite what it deletes");
        close();
        return false;
    }
    Query query(db_);
    for (const char* const statement : {
             "CREATE TABLE IF NOT EXISTS messages ("
             "id INTEGER PRIMARY KEY AUTOINCREMENT,"
             "peer TEXT NOT NULL, outgoing INTEGER, type TEXT, e2eId TEXT,"
             "text TEXT, attName TEXT, attMime TEXT, attSize INTEGER,"
             "attRef TEXT, attSrcPath TEXT, keyboard TEXT, edited INTEGER,"
             " ts INTEGER, status INTEGER, orderKey INTEGER, savedPath TEXT,"
             " replyTo TEXT, hasPicture INTEGER,"
             " attDurationMs INTEGER, attWave TEXT, forwarded INTEGER, device TEXT)",
             "CREATE TABLE IF NOT EXISTS read_state ("
             "peer TEXT PRIMARY KEY, last_read_id INTEGER NOT NULL)",
             "CREATE TABLE IF NOT EXISTS reactions ("
             "peer TEXT, target TEXT, reactor TEXT, emoji TEXT,"
             " PRIMARY KEY (peer, target, reactor))",
             "CREATE TABLE IF NOT EXISTS pinned_chats (peer TEXT PRIMARY KEY)",
             "CREATE TABLE IF NOT EXISTS group_posts ("
             "peer TEXT, e2eId TEXT, author TEXT, contactable INTEGER,"
             " PRIMARY KEY (peer, e2eId))",
             "CREATE TABLE IF NOT EXISTS group_reaction_counts ("
             "peer TEXT, target TEXT, emoji TEXT, count INTEGER,"
             " PRIMARY KEY (peer, target, emoji))",
             "CREATE TABLE IF NOT EXISTS group_state ("
             "peer TEXT PRIMARY KEY, kind TEXT, members INTEGER, write INTEGER,"
             " admin INTEGER, at INTEGER)",
             "CREATE TABLE IF NOT EXISTS group_members ("
             "peer TEXT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (peer, name))",
             "CREATE TABLE IF NOT EXISTS group_rosters ("
             "peer TEXT PRIMARY KEY, state INTEGER NOT NULL, own TEXT NOT NULL)",
             "CREATE TABLE IF NOT EXISTS group_mentions ("
             "id INTEGER PRIMARY KEY, peer TEXT NOT NULL)",
             "CREATE INDEX IF NOT EXISTS group_mentions_by_peer ON group_mentions (peer, id)",
             "CREATE TABLE IF NOT EXISTS chat_timers ("
             "peer TEXT PRIMARY KEY, seconds INTEGER NOT NULL)",
             "CREATE TABLE IF NOT EXISTS bot_menus (peer TEXT PRIMARY KEY, items TEXT NOT NULL)",
             "CREATE TABLE IF NOT EXISTS expiries ("
             "id INTEGER PRIMARY KEY, peer TEXT NOT NULL, at INTEGER NOT NULL)",
             "CREATE INDEX IF NOT EXISTS expiries_by_at ON expiries (at)",
             "CREATE UNIQUE INDEX IF NOT EXISTS messages_by_e2e"
             " ON messages (peer, e2eId, outgoing) WHERE e2eId != ''",
             "CREATE INDEX IF NOT EXISTS messages_by_peer_id ON messages (peer, id)",
             "CREATE INDEX IF NOT EXISTS messages_by_peer_order ON messages (peer, orderKey, id)",
             "CREATE INDEX IF NOT EXISTS messages_unread"
             " ON messages (peer, outgoing, id, type)"}) {
        if (!query.exec(statement)) {
            return failed();
        }
    }
    return true;
}

std::int64_t TranscriptStore::append(const StoredMessage& message)
{
    Transaction change(db_);
    if (!change.begun()) {
        failed();
        return 0;
    }
    if (!message.e2eId.empty()) {
        if (const std::int64_t existing = idForKey(message.peer, message.e2eId, message.outgoing);
            existing != 0) {
            log::info("transcript: {} was offered again; the row it already has stands",
                message.e2eId);
            return existing;
        }
    }
    Query query(db_);
    query.prepare(
        "INSERT INTO messages (peer, outgoing, type, e2eId, text, attName, attMime,"
        " attSize, attRef, attSrcPath, keyboard, edited, ts, status, orderKey, replyTo,"
        " attDurationMs, attWave, forwarded, device)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    query.bind(message.peer);
    query.bind(message.outgoing ? 1 : 0);
    query.bind(message.type);
    query.bind(message.e2eId);
    query.bind(message.text);
    query.bind(message.attName);
    query.bind(message.attMime);
    query.bind(message.attSize);
    query.bind(message.attRef);
    query.bind(message.attSrcPath);
    query.bind(message.keyboard);
    query.bind(message.edited ? 1 : 0);
    query.bind(message.ts);
    query.bind(message.status);
    query.bind(message.orderKey);
    query.bind(message.replyTo);
    query.bind(message.attDurationMs);
    query.bind(message.attWave);
    query.bind(message.forwarded ? 1 : 0);
    query.bind(message.device);
    if (!query.exec()) {
        failed();
        return 0;
    }
    const std::int64_t id = query.lastInsertId();
    if (message.outgoing && expires(message.type)) {
        const std::int64_t seconds = chatTimer(message.peer);
        if (seconds > 0
            && !stampExpiry(id, message.peer, message.ts + seconds * kMillisPerSecond)) {
            return 0;
        }
    }
    if (!message.author.empty() || message.fromHost) {
        Query post(db_);
        post.prepare("INSERT OR REPLACE INTO group_posts (peer, e2eId, author, contactable)"
                     " VALUES (?, ?, ?, ?)");
        post.bind(message.peer);
        post.bind(message.e2eId);
        post.bind(message.author);
        post.bind(message.contactable ? 1 : 0);
        if (!post.exec()) {
            failed();
            return 0;
        }
    }
    if (message.mentionsMe) {
        Query mention(db_);
        mention.prepare("INSERT INTO group_mentions (id, peer) VALUES (?, ?)");
        mention.bind(id);
        mention.bind(message.peer);
        if (!mention.exec()) {
            failed();
            return 0;
        }
    }
    if (!change.commit()) {
        failed();
        return 0;
    }
    return id;
}

std::int64_t TranscriptReader::idForKey(
    const std::string& peer, const std::string& e2eId, const bool outgoing) const
{
    if (e2eId.empty()) {
        return 0;
    }
    Query query(db_);
    query.prepare("SELECT id FROM messages WHERE peer = ? AND e2eId = ? AND outgoing = ? LIMIT 1");
    query.bind(peer);
    query.bind(e2eId);
    query.bind(outgoing ? 1 : 0);
    return readNumber(query);
}

bool TranscriptStore::updateStatus(const std::int64_t id, const int status)
{
    Query query(db_);
    query.prepare("UPDATE messages SET status = ? WHERE id = ?");
    query.bind(status);
    query.bind(id);
    return query.exec() || failed();
}

std::optional<bool> TranscriptStore::advanceStatus(const std::int64_t id, const int status)
{
    Query query(db_);
    query.prepare("UPDATE messages SET status = ? WHERE id = ? AND (? = ? OR status < ?)");
    query.bind(status);
    query.bind(id);
    query.bind(status);
    query.bind(static_cast<int>(DeliveryState::eFailed));
    query.bind(status);
    if (!query.exec()) {
        failed();
        return std::nullopt;
    }
    return query.changes() > 0;
}

std::vector<StoredMessage> TranscriptReader::latestMessages(
    const std::string& peer, const int limit) const
{
    Query query(db_);
    query.prepare(
        "SELECT " + kMessageColumns + " FROM messages WHERE peer = ? ORDER BY id DESC LIMIT ?");
    query.bind(peer);
    query.bind(limit);
    return readMessageRows(query);
}

std::vector<StoredMessage> TranscriptReader::olderMessages(
    const std::string& peer, const std::int64_t beforeId, const int limit) const
{
    Query query(db_);
    query.prepare("SELECT " + kMessageColumns
        + " FROM messages WHERE peer = ? AND id < ? ORDER BY id DESC LIMIT ?");
    query.bind(peer);
    query.bind(beforeId);
    query.bind(limit);
    return readMessageRows(query);
}

StoredMessage TranscriptReader::nextVoiceAfter(
    const std::string& peer, const std::int64_t afterId) const
{
    Query query(db_);
    query.prepare("SELECT " + kMessageColumns
        + " FROM messages WHERE peer = ? AND id > ? AND type = ? ORDER BY id ASC LIMIT 1");
    query.bind(peer);
    query.bind(afterId);
    query.bind(kTypeAudio);
    return readOneMessage(query);
}

StoredMessage TranscriptReader::pictureBeside(
    const std::string& peer, const std::int64_t id, const bool later) const
{
    Query query(db_);
    query.prepare("SELECT " + kMessageColumns
        + (later ? " FROM messages WHERE peer = ? AND id > ? AND type = ?"
                   " ORDER BY id ASC LIMIT 1"
                 : " FROM messages WHERE peer = ? AND id < ? AND type = ?"
                   " ORDER BY id DESC LIMIT 1"));
    query.bind(peer);
    query.bind(id);
    query.bind(kTypeImage);
    return readOneMessage(query);
}

std::vector<StoredMessage> TranscriptReader::newerMessages(
    const std::string& peer, const std::int64_t afterId, const int limit) const
{
    Query query(db_);
    query.prepare("SELECT " + kMessageColumns
        + " FROM messages WHERE peer = ? AND id > ? ORDER BY id ASC LIMIT ?");
    query.bind(peer);
    query.bind(afterId);
    query.bind(limit);
    return readMessageRows(query);
}

std::vector<StoredMessage> TranscriptReader::messagesAround(
    const std::string& peer, const std::int64_t id, const int perSide) const
{
    std::vector<StoredMessage> result = olderMessages(peer, id + 1, perSide + 1);
    const std::vector<StoredMessage> newer = newerMessages(peer, id, perSide);
    result.insert(result.end(), newer.begin(), newer.end());
    sortByOrder(result);
    return result;
}

bool TranscriptReader::hasMessagesBefore(const std::string& peer, const std::int64_t id) const
{
    Query query(db_);
    query.prepare("SELECT 1 FROM messages WHERE peer = ? AND id < ? LIMIT 1");
    query.bind(peer);
    query.bind(id);
    return query.exec() && query.next();
}

bool TranscriptReader::hasMessagesAfter(const std::string& peer, const std::int64_t id) const
{
    Query query(db_);
    query.prepare("SELECT 1 FROM messages WHERE peer = ? AND id > ? LIMIT 1");
    query.bind(peer);
    query.bind(id);
    return query.exec() && query.next();
}

std::vector<SearchableRow> TranscriptReader::searchableRows(const std::string& peer) const
{
    std::vector<SearchableRow> rows;
    Query query(db_);
    query.prepare("SELECT id, ts, text, outgoing, attName, type FROM messages"
                  " WHERE peer = ? AND (text <> '' OR attName <> '') ORDER BY id DESC");
    query.bind(peer);
    if (!query.exec()) {
        return rows;
    }
    while (query.next()) {
        rows.push_back({query.number(0), query.number(1), query.text(2), query.text(4),
            query.text(5), query.flag(3)});
    }
    return rows;
}

std::optional<std::vector<UnsentRow>> TranscriptStore::unsentOutgoing(
    const int preparingStatus, const int deliveringStatus)
{
    Query query(db_);
    query.prepare("SELECT id, peer, e2eId FROM messages WHERE outgoing = 1 AND status IN (?, ?)"
                  " ORDER BY id");
    query.bind(preparingStatus);
    query.bind(deliveringStatus);
    if (!query.exec()) {
        failed();
        return std::nullopt;
    }
    std::vector<UnsentRow> rows;
    while (query.next()) {
        rows.push_back({query.number(0), query.text(1), query.text(2)});
    }
    return rows;
}

std::optional<int> TranscriptStore::settleUnfinishedNotes(const std::string& type,
    const int preparingStatus, const int settledStatus, const std::string& text)
{
    Query query(db_);
    query.prepare("UPDATE messages SET status = ?, text = ? WHERE type = ? AND status = ?");
    query.bind(settledStatus);
    query.bind(text);
    query.bind(type);
    query.bind(preparingStatus);
    if (!query.exec()) {
        failed();
        return std::nullopt;
    }
    return query.changes();
}

bool TranscriptStore::markOutgoingReadUpTo(const std::string& peer, const std::int64_t uptoId,
    const int readStatus, const int minStatus, const int maxStatus)
{
    Query query(db_);
    query.prepare("UPDATE messages SET status = ? WHERE outgoing = 1 AND peer = ? AND id <= ?"
                  " AND status >= ? AND status <= ?");
    query.bind(readStatus);
    query.bind(peer);
    query.bind(uptoId);
    query.bind(minStatus);
    query.bind(maxStatus);
    return query.exec() || failed();
}

bool TranscriptStore::setSavedPath(const std::int64_t id, const std::string& path)
{
    Query query(db_);
    query.prepare("UPDATE messages SET savedPath = ? WHERE id = ?");
    query.bind(path);
    query.bind(id);
    return query.exec() || failed();
}

Bytes TranscriptReader::media(const std::string& key) const
{
    Query query(db_);
    if (!query.prepare("SELECT value FROM state WHERE name = ?")) {
        return {};
    }
    query.bind(key);
    if (!query.exec() || !query.next()) {
        return {};
    }
    return query.blob(0);
}

bool TranscriptStore::keepMedia(const std::string& key, const Bytes& bytes)
{
    Query query(db_);
    query.prepare("INSERT OR IGNORE INTO state (name, value) VALUES (?, ?)");
    query.bind(key);
    query.bind(bytes);
    return query.exec() || failed();
}

bool TranscriptStore::setHasPicture(const std::int64_t id, const bool has)
{
    Query query(db_);
    query.prepare("UPDATE messages SET hasPicture = ? WHERE id = ?");
    query.bind(has ? 1 : 0);
    query.bind(id);
    return query.exec() || failed();
}

std::int64_t TranscriptReader::oldestOfType(
    const std::string& peer, const std::string& type, const bool outgoing) const
{
    Query query(db_);
    query.prepare("SELECT id FROM messages WHERE peer = ? AND type = ? AND outgoing = ?"
                  " ORDER BY id LIMIT 1");
    query.bind(peer);
    query.bind(type);
    query.bind(outgoing ? 1 : 0);
    return readNumber(query);
}

StoredMessage TranscriptReader::messageById(const std::int64_t id) const
{
    Query query(db_);
    query.prepare("SELECT " + kMessageColumns + " FROM messages WHERE id = ?");
    query.bind(id);
    return readOneMessage(query);
}

StoredMessage TranscriptReader::messageByE2e(const std::string& e2eId, const std::string& peer) const
{
    if (e2eId.empty()) {
        return {};
    }
    Query query(db_);
    query.prepare(
        "SELECT " + kMessageColumns + " FROM messages WHERE e2eId = ? AND peer = ? ORDER BY id LIMIT 1");
    query.bind(e2eId);
    query.bind(peer);
    return readOneMessage(query);
}

bool TranscriptStore::editContent(
    const std::int64_t id, const std::string& text, const std::string& keyboard)
{
    Query query(db_);
    query.prepare("UPDATE messages SET text = ?, keyboard = ?, edited = 1 WHERE id = ?");
    query.bind(text);
    query.bind(keyboard);
    query.bind(id);
    return (query.exec() || failed()) && dropDeletedFromLog();
}

bool TranscriptStore::setType(const std::int64_t id, const std::string& type)
{
    Query query(db_);
    query.prepare("UPDATE messages SET type = ? WHERE id = ?");
    query.bind(type);
    query.bind(id);
    return query.exec() || failed();
}

bool TranscriptStore::removeById(const std::int64_t id)
{
    Transaction change(db_);
    if (!change.begun()) {
        return failed();
    }
    if (!removeRow(id).has_value()) {
        return false;
    }
    return (change.commit() || failed()) && dropDeletedFromLog();
}

std::optional<std::vector<RemovedRow>> TranscriptStore::removeExpired(const std::int64_t nowMs)
{
    std::vector<RemovedRow> removed;
    const std::vector<std::pair<std::string, std::int64_t>> due = expiredBy(nowMs);
    if (due.empty()) {
        return removed;
    }
    Transaction change(db_);
    if (!change.begun()) {
        return failedRow();
    }
    for (const auto& [peer, id] : due) {
        std::optional<std::string> e2eId = removeRow(id);
        if (!e2eId.has_value()) {
            return std::nullopt;
        }
        removed.push_back({peer, id, std::move(*e2eId)});
    }
    if (!(change.commit() || failed()) || !dropDeletedFromLog()) {
        return std::nullopt;
    }
    return removed;
}

bool TranscriptStore::dropDeletedFromLog()
{
    Query checkpoint(db_);
    if (!checkpoint.exec("PRAGMA wal_checkpoint(TRUNCATE)")) {
        return failed();
    }
    if (checkpoint.number(0) != 0) {
        lastError_ = "what was deleted is still in the write-ahead log: the database is being read";
        return false;
    }
    return true;
}

std::optional<std::string> TranscriptStore::removeRow(const std::int64_t id)
{
    std::string named;
    Query naming(db_);
    naming.prepare("SELECT e2eId FROM messages WHERE id = ?");
    naming.bind(id);
    if (!naming.exec()) {
        return failedRow();
    }
    if (naming.next()) {
        named = naming.text(0);
    }
    Query sharing(db_);
    sharing.prepare("SELECT 1 FROM messages WHERE e2eId = ? AND id <> ? LIMIT 1");
    sharing.bind(named);
    sharing.bind(id);
    if (!sharing.exec()) {
        return failedRow();
    }
    // Another chat holds a message under the same id: what hangs off that id is its, too.
    if (sharing.next()) {
        named.clear();
    }
    if (!named.empty() && !removeMediaOfMessage(named)) {
        return std::nullopt;
    }
    if (!named.empty()) {
        for (const char* const statement : {"DELETE FROM reactions WHERE target = ?",
                 "DELETE FROM group_reaction_counts WHERE target = ?",
                 "DELETE FROM group_posts WHERE e2eId = ?"}) {
            Query side(db_);
            side.prepare(statement);
            side.bind(named);
            if (!side.exec()) {
                return failedRow();
            }
        }
    }
    for (const char* const statement : {"DELETE FROM expiries WHERE id = ?",
             "DELETE FROM group_mentions WHERE id = ?", "DELETE FROM messages WHERE id = ?"}) {
        Query query(db_);
        query.prepare(statement);
        query.bind(id);
        if (!query.exec()) {
            return failedRow();
        }
    }
    return named;
}

bool TranscriptStore::clearPeerRows(const std::string& peer)
{
    if (!removeMediaOfPeer(peer)) {
        return false;
    }
    for (const char* const statement : {"DELETE FROM messages WHERE peer = ?",
             "DELETE FROM expiries WHERE peer = ?", "DELETE FROM reactions WHERE peer = ?",
             "DELETE FROM read_state WHERE peer = ?", "DELETE FROM group_posts WHERE peer = ?",
             "DELETE FROM group_reaction_counts WHERE peer = ?",
             "DELETE FROM group_mentions WHERE peer = ?"}) {
        Query query(db_);
        query.prepare(statement);
        query.bind(peer);
        if (!query.exec()) {
            return failed();
        }
    }
    return true;
}

bool TranscriptStore::clearPeer(const std::string& peer)
{
    Transaction change(db_);
    if (!change.begun()) {
        return failed();
    }
    if (!clearPeerRows(peer)) {
        return false;
    }
    return (change.commit() || failed()) && dropDeletedFromLog();
}

bool TranscriptStore::forgetPeer(const std::string& peer)
{
    Transaction change(db_);
    if (!change.begun()) {
        return failed();
    }
    if (!clearPeerRows(peer)) {
        return false;
    }
    for (const char* const statement : {"DELETE FROM pinned_chats WHERE peer = ?",
             "DELETE FROM chat_timers WHERE peer = ?", "DELETE FROM bot_menus WHERE peer = ?",
             "DELETE FROM group_state WHERE peer = ?", "DELETE FROM group_members WHERE peer = ?",
             "DELETE FROM group_rosters WHERE peer = ?"}) {
        Query query(db_);
        query.prepare(statement);
        query.bind(peer);
        if (!query.exec()) {
            return failed();
        }
    }
    return (change.commit() || failed()) && dropDeletedFromLog();
}

bool TranscriptStore::setGroupState(const std::string& peer, const GroupState& state)
{
    Query query(db_);
    query.prepare("INSERT OR REPLACE INTO group_state (peer, kind, members, write, admin, at)"
                  " VALUES (?, ?, ?, ?, ?, ?)");
    query.bind(peer);
    query.bind(state.kind);
    query.bind(state.members);
    query.bind(state.write ? 1 : 0);
    query.bind(state.admin ? 1 : 0);
    query.bind(state.at);
    return query.exec() || failed();
}

std::optional<GroupState> TranscriptReader::groupState(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT kind, members, write, admin, at FROM group_state WHERE peer = ?");
    query.bind(peer);
    if (!query.exec() || !query.next()) {
        return std::nullopt;
    }
    return GroupState{
        query.text(0), query.number(1), query.flag(2), query.flag(3), query.number(4)};
}

bool TranscriptStore::dropGroupState(const std::string& peer)
{
    Transaction change(db_);
    if (!change.begun()) {
        return failed();
    }
    for (const char* const statement : {"DELETE FROM group_state WHERE peer = ?",
             "DELETE FROM group_members WHERE peer = ?", "DELETE FROM group_rosters WHERE peer = ?"}) {
        Query query(db_);
        query.prepare(statement);
        query.bind(peer);
        if (!query.exec()) {
            return failed();
        }
    }
    return change.commit() || failed();
}

std::vector<std::string> TranscriptReader::groupMembers(const std::string& peer) const
{
    std::vector<std::string> names;
    Query query(db_);
    query.prepare("SELECT name FROM group_members WHERE peer = ? ORDER BY name");
    query.bind(peer);
    if (!query.exec()) {
        return names;
    }
    while (query.next()) {
        names.push_back(query.text(0));
    }
    return names;
}

MemberListState TranscriptReader::memberListState(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT state FROM group_rosters WHERE peer = ?");
    query.bind(peer);
    if (!query.exec() || !query.next()) {
        return MemberListState::eUnknown;
    }
    return static_cast<MemberListState>(query.number(0));
}

std::string TranscriptReader::ownGroupName(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT own FROM group_rosters WHERE peer = ?");
    query.bind(peer);
    if (!query.exec() || !query.next()) {
        return {};
    }
    return query.text(0);
}

int TranscriptReader::unreadMentionCount(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT COUNT(*) FROM group_mentions n JOIN messages m ON m.id = n.id"
                  " WHERE n.peer = ? AND m.id >"
                  " (SELECT COALESCE(MAX(last_read_id), 0) FROM read_state WHERE peer = ?)");
    query.bind(peer);
    query.bind(peer);
    return static_cast<int>(readNumber(query));
}

std::int64_t TranscriptReader::firstUnreadMentionId(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT MIN(m.id) FROM group_mentions n JOIN messages m ON m.id = n.id"
                  " WHERE n.peer = ? AND m.id >"
                  " (SELECT COALESCE(MAX(last_read_id), 0) FROM read_state WHERE peer = ?)");
    query.bind(peer);
    query.bind(peer);
    if (!query.exec() || !query.next() || query.isNull(0)) {
        return 0;
    }
    return query.number(0);
}

bool TranscriptStore::replaceGroupMembers(
    const std::string& peer, const std::vector<std::string>& names)
{
    Transaction change(db_);
    if (!change.begun()) {
        return failed();
    }
    Query clear(db_);
    clear.prepare("DELETE FROM group_members WHERE peer = ?");
    clear.bind(peer);
    if (!clear.exec()) {
        return failed();
    }
    if (!addGroupMembers(peer, names) || !setMemberListState(peer, MemberListState::eHeld)) {
        return false;
    }
    return change.commit() || failed();
}

bool TranscriptStore::addGroupMembers(const std::string& peer, const std::vector<std::string>& names)
{
    for (const std::string& name : names) {
        Query insert(db_);
        insert.prepare("INSERT OR IGNORE INTO group_members (peer, name) VALUES (?, ?)");
        insert.bind(peer);
        insert.bind(name);
        if (!insert.exec()) {
            return failed();
        }
    }
    return true;
}

bool TranscriptStore::removeGroupMembers(
    const std::string& peer, const std::vector<std::string>& names)
{
    for (const std::string& name : names) {
        Query remove(db_);
        remove.prepare("DELETE FROM group_members WHERE peer = ? AND name = ?");
        remove.bind(peer);
        remove.bind(name);
        if (!remove.exec()) {
            return failed();
        }
    }
    return true;
}

bool TranscriptStore::setMemberListState(const std::string& peer, const MemberListState state)
{
    Query query(db_);
    query.prepare("INSERT INTO group_rosters (peer, state, own) VALUES (?, ?, '')"
                  " ON CONFLICT (peer) DO UPDATE SET state = excluded.state");
    query.bind(peer);
    query.bind(static_cast<int>(state));
    if (!query.exec()) {
        return failed();
    }
    if (state != MemberListState::eNone) {
        return true;
    }
    Query clear(db_);
    clear.prepare("DELETE FROM group_members WHERE peer = ?");
    clear.bind(peer);
    return clear.exec() || failed();
}

bool TranscriptStore::setOwnGroupName(const std::string& peer, const std::string& name)
{
    Query query(db_);
    query.prepare("INSERT INTO group_rosters (peer, state, own) VALUES (?, ?, ?)"
                  " ON CONFLICT (peer) DO UPDATE SET own = excluded.own");
    query.bind(peer);
    query.bind(static_cast<int>(MemberListState::eUnknown));
    query.bind(name);
    return query.exec() || failed();
}

bool TranscriptStore::setMentionsMe(const std::int64_t id, const std::string& peer, const bool mentions)
{
    Query query(db_);
    if (mentions) {
        query.prepare("INSERT OR IGNORE INTO group_mentions (id, peer) VALUES (?, ?)");
        query.bind(id);
        query.bind(peer);
    } else {
        query.prepare("DELETE FROM group_mentions WHERE id = ?");
        query.bind(id);
    }
    return query.exec() || failed();
}

bool TranscriptStore::setGroupReactionCounts(const std::string& peer, const std::string& target,
    const std::map<std::string, std::int64_t>& counts)
{
    Transaction change(db_);
    if (!change.begun()) {
        return failed();
    }
    Query clear(db_);
    clear.prepare("DELETE FROM group_reaction_counts WHERE peer = ? AND target = ?");
    clear.bind(peer);
    clear.bind(target);
    if (!clear.exec()) {
        return failed();
    }
    for (const auto& [emoji, count] : counts) {
        Query insert(db_);
        insert.prepare("INSERT INTO group_reaction_counts (peer, target, emoji, count)"
                       " VALUES (?, ?, ?, ?)");
        insert.bind(peer);
        insert.bind(target);
        insert.bind(emoji);
        insert.bind(count);
        if (!insert.exec()) {
            return failed();
        }
    }
    return change.commit() || failed();
}

std::map<std::string, std::int64_t> TranscriptReader::groupReactionCounts(
    const std::string& peer, const std::string& target) const
{
    std::map<std::string, std::int64_t> counts;
    Query query(db_);
    query.prepare("SELECT emoji, count FROM group_reaction_counts WHERE peer = ? AND target = ?");
    query.bind(peer);
    query.bind(target);
    if (!query.exec()) {
        return counts;
    }
    while (query.next()) {
        counts[query.text(0)] = query.number(1);
    }
    return counts;
}

std::vector<std::string> TranscriptReader::conversationPeers() const
{
    std::vector<std::string> peers;
    Query query(db_);
    if (query.exec(kEachPeer + " SELECT peer FROM peers")) {
        while (query.next()) {
            peers.push_back(query.text(0));
        }
    }
    return peers;
}

LastMessage TranscriptReader::lastMessage(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT text, type, attName, (SELECT author FROM group_posts g"
                  " WHERE g.peer = messages.peer AND g.e2eId = messages.e2eId)"
                  " FROM messages WHERE peer = ?"
                  " AND (text != '' OR type IN (?, ?, ?))"
                  " ORDER BY orderKey DESC, id DESC LIMIT 1");
    query.bind(peer);
    query.bind(kTypeFile);
    query.bind(kTypeImage);
    query.bind(kTypeAudio);
    if (!query.exec() || !query.next()) {
        return {};
    }
    const std::string text = query.text(0);
    if (!text.empty()) {
        return {text, query.text(1), {}, query.text(3)};
    }
    return {{}, query.text(1), query.text(2), query.text(3)};
}

std::int64_t TranscriptReader::newestOrderKey(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT MAX(orderKey) FROM messages WHERE peer = ?");
    query.bind(peer);
    return readNumber(query);
}

std::int64_t TranscriptReader::newestOrderKey(const std::string& peer, const bool outgoing) const
{
    Query query(db_);
    query.prepare("SELECT MAX(orderKey) FROM messages WHERE peer = ? AND outgoing = ?");
    query.bind(peer);
    query.bind(outgoing ? 1 : 0);
    return readNumber(query);
}

std::int64_t TranscriptReader::orderKeyOf(const std::string& peer, const std::string& e2eId) const
{
    if (e2eId.empty()) {
        return 0;
    }
    Query query(db_);
    query.prepare("SELECT MAX(orderKey) FROM messages WHERE peer = ? AND e2eId = ?");
    query.bind(peer);
    query.bind(e2eId);
    return readNumber(query);
}

std::string TranscriptReader::idPlacedBefore(
    const std::string& peer, const std::int64_t orderKey, const std::int64_t id) const
{
    Query query(db_);
    query.prepare("SELECT e2eId FROM messages WHERE peer = ? AND e2eId != ''"
                  " AND (orderKey < ? OR (orderKey = ? AND id < ?))"
                  " ORDER BY orderKey DESC, id DESC LIMIT 1");
    query.bind(peer);
    query.bind(orderKey);
    query.bind(orderKey);
    query.bind(id);
    if (!query.exec() || !query.next()) {
        return {};
    }
    return query.text(0);
}

std::int64_t TranscriptReader::lastTime(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT ts FROM messages WHERE peer = ? ORDER BY orderKey DESC, id DESC LIMIT 1");
    query.bind(peer);
    return readNumber(query);
}

bool TranscriptStore::setLastReadId(const std::string& peer, const std::int64_t id)
{
    if (peer.empty() || id <= 0) {
        return true;
    }
    Transaction change(db_);
    if (!change.begun()) {
        return failed();
    }
    const std::int64_t before = lastReadId(peer);
    Query query(db_);
    query.prepare("INSERT OR REPLACE INTO read_state (peer, last_read_id) VALUES (?,"
                  " max(?, coalesce((SELECT last_read_id FROM read_state WHERE peer = ?), 0)))");
    query.bind(peer);
    query.bind(id);
    query.bind(peer);
    if (!query.exec() || !stampNewlyRead(peer, before, lastReadId(peer)) || !change.commit()) {
        return failed();
    }
    return true;
}

bool TranscriptStore::applyReadThrough(const std::string& peer, const std::int64_t sentAtMs)
{
    if (peer.empty() || sentAtMs <= 0) {
        return true;
    }
    Transaction change(db_);
    if (!change.begun()) {
        return failed();
    }
    const std::int64_t before = lastReadId(peer);
    Query query(db_);
    query.prepare("INSERT OR REPLACE INTO read_state (peer, last_read_id) VALUES (?,"
                  " max(coalesce((SELECT last_read_id FROM read_state WHERE peer = ?), 0),"
                  " coalesce((SELECT MAX(id) FROM messages WHERE peer = ? AND outgoing = 0"
                  " AND type != ? AND ts <= ?), 0)))");
    query.bind(peer);
    query.bind(peer);
    query.bind(peer);
    query.bind(kTypeSystem);
    query.bind(sentAtMs);
    if (!query.exec() || !stampNewlyRead(peer, before, lastReadId(peer)) || !change.commit()) {
        return failed();
    }
    return true;
}

void TranscriptStore::onExpiryStamped(std::function<void(std::int64_t atMs)> tell)
{
    expiryStamped_ = std::move(tell);
}

bool TranscriptStore::stampExpiry(
    const std::int64_t id, const std::string& peer, const std::int64_t atMs)
{
    Query query(db_);
    query.prepare("INSERT OR IGNORE INTO expiries (id, peer, at) VALUES (?, ?, ?)");
    query.bind(id);
    query.bind(peer);
    query.bind(atMs);
    if (!query.exec()) {
        return failed();
    }
    if (query.changes() > 0 && expiryStamped_) {
        expiryStamped_(atMs);
    }
    return true;
}

bool TranscriptStore::stampNewlyRead(
    const std::string& peer, const std::int64_t afterId, const std::int64_t uptoId)
{
    const std::int64_t seconds = chatTimer(peer);
    if (seconds <= 0 || uptoId <= afterId) {
        return true;
    }
    const std::int64_t atMs = nowMillis() + seconds * kMillisPerSecond;
    Query query(db_);
    query.prepare("INSERT OR IGNORE INTO expiries (id, peer, at)"
                  " SELECT id, peer, ? FROM messages WHERE peer = ? AND outgoing = 0"
                  " AND id > ? AND id <= ? AND type IN ("
        + expiringTypesSql() + ")");
    query.bind(atMs);
    query.bind(peer);
    query.bind(afterId);
    query.bind(uptoId);
    if (!query.exec()) {
        return failed();
    }
    if (query.changes() > 0 && expiryStamped_) {
        expiryStamped_(atMs);
    }
    return true;
}

std::int64_t TranscriptReader::chatTimer(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT seconds FROM chat_timers WHERE peer = ? LIMIT 1");
    query.bind(peer);
    return readNumber(query);
}

bool TranscriptStore::setChatTimer(const std::string& peer, const std::int64_t seconds)
{
    Query query(db_);
    if (seconds > 0) {
        query.prepare("INSERT OR REPLACE INTO chat_timers (peer, seconds) VALUES (?, ?)");
        query.bind(peer);
        query.bind(seconds);
    } else {
        query.prepare("DELETE FROM chat_timers WHERE peer = ?");
        query.bind(peer);
    }
    return query.exec() || failed();
}

std::string TranscriptReader::botMenu(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT items FROM bot_menus WHERE peer = ? LIMIT 1");
    query.bind(peer);
    if (!query.exec() || !query.next()) {
        return {};
    }
    return query.text(0);
}

bool TranscriptStore::setBotMenu(const std::string& peer, const std::string& itemsJson)
{
    const nlohmann::json items = parseJsonOrDiscarded(itemsJson);
    Query query(db_);
    if (!items.is_array() || items.empty()) {
        query.prepare("DELETE FROM bot_menus WHERE peer = ?");
        query.bind(peer);
    } else {
        query.prepare("INSERT OR REPLACE INTO bot_menus (peer, items) VALUES (?, ?)");
        query.bind(peer);
        query.bind(itemsJson);
    }
    return query.exec() || failed();
}

std::vector<std::pair<std::string, std::int64_t>> TranscriptReader::expiredBy(
    const std::int64_t nowMs) const
{
    std::vector<std::pair<std::string, std::int64_t>> due;
    Query query(db_);
    query.prepare("SELECT peer, id FROM expiries WHERE at <= ? ORDER BY at");
    query.bind(nowMs);
    if (query.exec()) {
        while (query.next()) {
            due.emplace_back(query.text(0), query.number(1));
        }
    }
    return due;
}

std::optional<std::int64_t> TranscriptReader::nextExpiryAt() const
{
    Query query(db_);
    query.prepare("SELECT at FROM expiries ORDER BY at LIMIT 1");
    if (!query.exec() || !query.next()) {
        return std::nullopt;
    }
    return query.number(0);
}

std::int64_t TranscriptReader::lastReadId(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT last_read_id FROM read_state WHERE peer = ? LIMIT 1");
    query.bind(peer);
    return readNumber(query);
}

bool TranscriptStore::setPinned(const std::string& peer, const bool pinned)
{
    if (peer.empty()) {
        return true;
    }
    Query query(db_);
    query.prepare(pinned ? "INSERT OR IGNORE INTO pinned_chats (peer) VALUES (?)"
                         : "DELETE FROM pinned_chats WHERE peer = ?");
    query.bind(peer);
    return query.exec() || failed();
}

bool TranscriptReader::isPinned(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT 1 FROM pinned_chats WHERE peer = ? LIMIT 1");
    query.bind(peer);
    return query.exec() && query.next();
}

int TranscriptReader::unreadCount(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT COUNT(*) FROM messages WHERE peer = ? AND outgoing = 0"
                  " AND type != ? AND id >"
                  " (SELECT COALESCE(MAX(last_read_id), 0) FROM read_state WHERE peer = ?)");
    query.bind(peer);
    query.bind(kTypeSystem);
    query.bind(peer);
    return static_cast<int>(readNumber(query));
}

int TranscriptReader::unreadTotal() const
{
    Query query(db_);
    query.prepare(kEachPeer
        + " SELECT COALESCE(SUM((SELECT COUNT(*) FROM messages m WHERE m.peer = p.peer"
          " AND m.outgoing = 0 AND m.type != ? AND m.id > (SELECT"
          " COALESCE(MAX(last_read_id), 0) FROM read_state r WHERE r.peer = p.peer))), 0)"
          " FROM peers p");
    query.bind(kTypeSystem);
    return static_cast<int>(readNumber(query));
}

std::int64_t TranscriptReader::firstUnreadId(const std::string& peer) const
{
    Query query(db_);
    query.prepare("SELECT MIN(id) FROM messages WHERE peer = ? AND outgoing = 0"
                  " AND type != ? AND id >"
                  " (SELECT COALESCE(MAX(last_read_id), 0) FROM read_state WHERE peer = ?)");
    query.bind(peer);
    query.bind(kTypeSystem);
    query.bind(peer);
    if (!query.exec() || !query.next() || query.isNull(0)) {
        return 0;
    }
    return query.number(0);
}

bool TranscriptStore::setReaction(const std::string& peer, const std::string& target,
    const std::string& reactor, const std::string& emoji)
{
    if (peer.empty() || target.empty() || reactor.empty()) {
        return true;
    }
    Query query(db_);
    if (emoji.empty()) {
        query.prepare("DELETE FROM reactions WHERE peer = ? AND target = ? AND reactor = ?");
        query.bind(peer);
        query.bind(target);
        query.bind(reactor);
    } else {
        query.prepare("INSERT OR REPLACE INTO reactions (peer, target, reactor, emoji)"
                      " VALUES (?, ?, ?, ?)");
        query.bind(peer);
        query.bind(target);
        query.bind(reactor);
        query.bind(emoji);
    }
    return query.exec() || failed();
}

std::vector<Reaction> TranscriptReader::reactionsFor(
    const std::string& peer, const std::string& target) const
{
    std::vector<Reaction> result;
    if (peer.empty() || target.empty()) {
        return result;
    }
    Query query(db_);
    query.prepare(
        "SELECT reactor, emoji FROM reactions WHERE peer = ? AND target = ? ORDER BY rowid");
    query.bind(peer);
    query.bind(target);
    if (!query.exec()) {
        return result;
    }
    while (query.next()) {
        result.push_back({query.text(0), query.text(1)});
    }
    return result;
}

bool TranscriptReader::hasMediaTable() const
{
    Query query(db_);
    return query.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'state'")
        && query.next();
}

bool TranscriptStore::removeMediaOfMessage(const std::string& e2eId)
{
    if (e2eId.empty() || !hasMediaTable()) {
        return true;
    }
    Query query(db_);
    query.prepare("DELETE FROM state WHERE name = ? OR name = ? OR name = ?");
    query.bind(kPictureKeyPrefix + e2eId);
    query.bind(kVoiceKeyPrefix + e2eId);
    query.bind(kFileKeyPrefix + e2eId);
    return query.exec() || failed();
}

bool TranscriptStore::failed()
{
    lastError_ = sqlite3_errmsg(db_.get());
    return false;
}

std::nullopt_t TranscriptStore::failedRow()
{
    static_cast<void>(failed());
    return std::nullopt;
}


bool TranscriptStore::removeMediaOfPeer(const std::string& peer)
{
    if (!hasMediaTable()) {
        return true;
    }
    Query query(db_);
    query.prepare(mediaOfRows("peer = ?"));
    query.bind(peer);
    query.bind(peer);
    return query.exec() || failed();
}

bool TranscriptStore::removeMediaOfTrimmed(const std::string& peer, const int keep)
{
    if (!hasMediaTable()) {
        return true;
    }
    Query query(db_);
    if (!query.prepare(mediaOfRows("peer = ? AND id NOT IN (SELECT id FROM messages"
                                   " WHERE peer = ? ORDER BY id DESC LIMIT ?)"))) {
        return false;
    }
    for (int half = 0; half < 2; ++half) {
        query.bind(peer);
        query.bind(peer);
        query.bind(keep);
    }
    return query.exec();
}

std::vector<ChatWeight> TranscriptReader::chatWeights() const
{
    std::vector<ChatWeight> weights;
    // A chat's rows lie across the whole table; walking them chat by chat rereads every page.
    const std::string rows = "SELECT peer, COUNT(*) AS messages, TOTAL(" + messageBytesExpression()
        + ") AS bytes FROM messages AS m NOT INDEXED GROUP BY peer";
    const std::string sql = hasMediaTable()
        ? "WITH kept AS (" + keptMediaRows()
            + ") SELECT r.peer, r.messages, r.bytes, COALESCE(k.bytes, 0), COALESCE(k.count, 0)"
              " FROM ("
            + rows
            + ") AS r LEFT JOIN (SELECT m.peer, TOTAL(kept.bytes) AS bytes, COUNT(*) AS count"
              " FROM kept JOIN messages AS m ON m.e2eId = kept.e2eId WHERE m.e2eId != ''"
              " GROUP BY m.peer) AS k ON k.peer = r.peer"
        : "SELECT peer, messages, bytes, 0, 0 FROM (" + rows + ")";
    Query query(db_);
    if (!query.exec(sql)) {
        return weights;
    }
    while (query.next()) {
        weights.push_back(
            {query.text(0), query.number(1), query.number(2), query.number(3), query.number(4)});
    }
    return weights;
}

DatabaseFootprint TranscriptReader::footprint() const
{
    DatabaseFootprint out;
    fs::path wal = path_;
    wal += "-wal";
    out.fileBytes = static_cast<std::int64_t>(sizeOrZero(path_) + sizeOrZero(wal));
    Query pageSize(db_);
    const std::int64_t bytesPerPage = pageSize.exec("PRAGMA page_size") ? pageSize.number(0) : 0;
    Query allPages(db_);
    Query freePages(db_);
    if (bytesPerPage > 0 && allPages.exec("PRAGMA page_count") && freePages.exec("PRAGMA freelist_count")) {
        out.freeBytes = out.fileBytes - bytesPerPage * (allPages.number(0) - freePages.number(0));
    }
    return out;
}

std::int64_t TranscriptStore::pruneRowsOf(const std::string& peer, const int keep)
{
    if (!removeMediaOfTrimmed(peer, keep)) {
        throw std::runtime_error("the media of trimmed messages could not be removed");
    }
    Query messages(db_);
    if (!messages.prepare("DELETE FROM messages WHERE peer = ? AND id NOT IN ("
                          "SELECT id FROM messages WHERE peer = ? ORDER BY id DESC LIMIT ?)")) {
        throw std::runtime_error("the conversation could not be trimmed");
    }
    messages.bind(peer);
    messages.bind(peer);
    messages.bind(keep);
    if (!messages.exec()) {
        throw std::runtime_error("the conversation could not be trimmed");
    }
    const std::int64_t removed = messages.changes();
    Query expiries(db_);
    if (!expiries.prepare("DELETE FROM expiries WHERE peer = ? AND id NOT IN ("
                          "SELECT id FROM messages WHERE peer = ?)")) {
        throw std::runtime_error("the timers of trimmed messages could not be removed");
    }
    expiries.bind(peer);
    expiries.bind(peer);
    if (!expiries.exec()) {
        throw std::runtime_error("the timers of trimmed messages could not be removed");
    }
    Query reactions(db_);
    if (!reactions.prepare("DELETE FROM reactions WHERE peer = ? AND target NOT IN ("
                           "SELECT e2eId FROM messages WHERE peer = ? AND e2eId != '')")) {
        throw std::runtime_error("the reactions of trimmed messages could not be removed");
    }
    reactions.bind(peer);
    reactions.bind(peer);
    if (!reactions.exec()) {
        throw std::runtime_error("the reactions of trimmed messages could not be removed");
    }
    Query mentions(db_);
    if (!mentions.prepare("DELETE FROM group_mentions WHERE peer = ? AND id NOT IN ("
                          "SELECT id FROM messages WHERE peer = ?)")) {
        throw std::runtime_error("the mentions of trimmed messages could not be removed");
    }
    mentions.bind(peer);
    mentions.bind(peer);
    if (!mentions.exec()) {
        throw std::runtime_error("the mentions of trimmed messages could not be removed");
    }
    return removed;
}

std::int64_t TranscriptStore::pruneToLatest(const std::string& peer, const int keep)
{
    if (peer.empty() || keep < 0) {
        return 0;
    }
    Transaction change(db_);
    if (!change.begun()) {
        throw std::runtime_error("the database is busy");
    }
    const std::int64_t removed = pruneRowsOf(peer, keep);
    if (!change.commit()) {
        throw std::runtime_error("the change could not be committed");
    }
    if (!dropDeletedFromLog()) {
        throw std::runtime_error(lastError_);
    }
    return removed;
}

std::int64_t TranscriptStore::pruneEveryChatToLatest(const int keep)
{
    if (keep < 0) {
        return 0;
    }
    const std::vector<std::string> peers = conversationPeers();
    Transaction change(db_);
    if (!change.begun()) {
        throw std::runtime_error("the database is busy");
    }
    std::int64_t removed = 0;
    for (const std::string& peer : peers) {
        removed += pruneRowsOf(peer, keep);
    }
    if (!change.commit()) {
        throw std::runtime_error("the change could not be committed");
    }
    if (!dropDeletedFromLog()) {
        throw std::runtime_error(lastError_);
    }
    return removed;
}

bool TranscriptStore::compact(std::string& reason)
{
    if (!vacuumsIncrementally(db_)) {
        reason = "the database was made without incremental vacuum";
        return false;
    }
    for (std::int64_t loose = freePages(); loose != 0;) {
        if (loose < 0) {
            reason = sqlite3_errmsg(db_.get());
            return false;
        }
        const auto stepStarted = std::chrono::steady_clock::now();
        if (sqlite3_exec(db_.get(), kVacuumStep.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
            reason = sqlite3_errmsg(db_.get());
            return false;
        }
        // A writer the step held off gets as long again to take its turn.
        std::this_thread::sleep_for(std::chrono::steady_clock::now() - stepStarted);
        const std::int64_t left = freePages();
        if (left >= loose) {
            reason = "the free pages did not go back to the disk";
            return false;
        }
        loose = left;
    }
    Query checkpoint(db_);
    if (!checkpoint.exec("PRAGMA wal_checkpoint(TRUNCATE)")) {
        reason = sqlite3_errmsg(db_.get());
        return false;
    }
    if (checkpoint.number(0) != 0) {
        reason = "the database is still being read";
        return false;
    }
    return true;
}

std::int64_t TranscriptStore::freePages() const
{
    Query count(db_);
    return count.exec("PRAGMA freelist_count") ? count.number(0) : kUnknownCount;
}

}  // namespace bazarish::client
