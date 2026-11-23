// Bazarish project (c) 2026
#include "AccountDb.hpp"
#include "AccountKey.hpp"
#include "AccountManager.hpp"
#include "EpochRing.hpp"
#include "KeyedDatabase.hpp"
#include "PresenceSeed.hpp"
#include "Session.hpp"
#include "TranscriptDb.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Epochs.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PrivateFile.hpp>

#include "PageScan.hpp"
#include "TestUtil.hpp"

#include <sqlcipher/sqlite3.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;
using testutil::filesHold;

namespace {

namespace fs = std::filesystem;

constexpr std::size_t kRowBytes = 64 * 1024;
constexpr std::size_t kLargeRows = 768;
// SQLite's heap may grow by at most this fraction of the database while it is re-encrypted.
constexpr std::int64_t kHeapShareOfDatabase = 8;

constexpr std::size_t kMagicBytes = 4;
constexpr std::size_t kMemoryAt = kMagicBytes;
constexpr std::size_t kPassesAt = kMemoryAt + sizeof(std::uint32_t);
constexpr std::size_t kSaltAt = kPassesAt + sizeof(std::uint32_t);
constexpr std::size_t kNonceAt = kSaltAt + 16;
constexpr std::size_t kBodyAt = kNonceAt + 12;
constexpr std::uint32_t kAtRestMemoryKiB = 64 * 1024;
constexpr std::uint32_t kAtRestPasses = 3;
constexpr std::uint32_t kEndlessPasses = 1U << 30;
constexpr std::uint32_t kSmallestMemoryKiB = 8;
constexpr std::chrono::seconds kRefusalTime{1};

constexpr EpochNumber kMonthsAgo = 6;
constexpr std::size_t kMessageIdBytes = 8;
constexpr std::int64_t kMsPerSecond = 1000;
constexpr std::int64_t kLongAgoMs = 1'000'000'000'000;
// PRAGMA auto_vacuum reads 2 for INCREMENTAL.
constexpr std::int64_t kIncrementalVacuum = 2;
constexpr int kErasedLines = 400;
constexpr std::size_t kLinePaddingBytes = 1500;

std::uint32_t wordAt(const Bytes& bytes, const std::size_t at)
{
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < sizeof value; ++i) {
        value |= static_cast<std::uint32_t>(bytes.at(at + i)) << (8 * i);
    }
    return value;
}

void putWord(Bytes& bytes, const std::size_t at, const std::uint32_t value)
{
    for (std::size_t i = 0; i < sizeof value; ++i) {
        bytes.at(at + i) = static_cast<unsigned char>((value >> (8 * i)) & 0xFF);
    }
}

fs::path suffixed(fs::path file, const std::string& suffix)
{
    file += suffix;
    return file;
}

std::int64_t vacuumModeOf(const fs::path& file, const SecretBytes& key)
{
    const Database db(openKeyed(file, key), "vacuum mode");
    Statement mode(db, "PRAGMA auto_vacuum");
    CHECK(mode.step());
    return mode.number(0);
}

void checkBackup()
{
    const std::string text = "the account, every key of it";
    const Bytes plain(text.begin(), text.end());
    const Bytes sealed = accountkey::sealBackup(plain, "bundle-pw");
    CHECK(Bytes(sealed.begin(), sealed.begin() + kMagicBytes) == Bytes({'B', 'Z', 'E', '1'}));
    CHECK(wordAt(sealed, kMemoryAt) == kAtRestMemoryKiB);
    CHECK(wordAt(sealed, kPassesAt) == kAtRestPasses);
    CHECK(accountkey::openBackup(sealed, "bundle-pw").bytes() == plain);
    CHECK(accountkey::sealBackup(plain, "bundle-pw") != sealed);
    CHECK_THROWS(accountkey::openBackup(sealed, "wrong-pw"));
    CHECK_THROWS(accountkey::openBackup(sealed, ""));
    CHECK_THROWS(accountkey::sealBackup(plain, ""));
    CHECK_THROWS(accountkey::openBackup(Bytes(sealed.begin(), sealed.begin() + kBodyAt), "bundle-pw"));

    for (const std::size_t at :
        {std::size_t{0}, kMemoryAt, kPassesAt, kSaltAt, kNonceAt, kBodyAt, sealed.size() - 1}) {
        Bytes tampered = sealed;
        tampered.at(at) ^= 0x01;
        CHECK_THROWS(accountkey::openBackup(tampered, "bundle-pw"));
    }

    Bytes greedy = sealed;
    putWord(greedy, kMemoryAt, kSmallestMemoryKiB);
    putWord(greedy, kPassesAt, kEndlessPasses);
    const auto started = std::chrono::steady_clock::now();
    CHECK_THROWS(accountkey::openBackup(greedy, "bundle-pw"));
    CHECK(std::chrono::steady_clock::now() - started < kRefusalTime);
    Bytes hungry = sealed;
    putWord(hungry, kMemoryAt, UINT32_MAX);
    CHECK_THROWS(accountkey::openBackup(hungry, "bundle-pw"));
}

void checkLargeRekey(const fs::path& dir)
{
    const fs::path file = dir / "large.db";
    {
        AccountDb db(file, "old pass");
        for (std::size_t row = 0; row < kLargeRows; ++row) {
            db.put("row-" + std::to_string(row), randomBytes(kRowBytes));
        }
    }
    {
        TranscriptStore store;
        CHECK(store.open(file, "old pass"));
    }
    const SecretBytes oldKey = accountkey::keyFor(file, "old pass");
    const Bytes lastRow = *AccountDb(file, "old pass").get("row-" + std::to_string(kLargeRows - 1));
    const std::int64_t databaseBytes = static_cast<std::int64_t>(fs::file_size(file));
    CHECK(databaseBytes > static_cast<std::int64_t>(kRowBytes * kLargeRows));
    CHECK(vacuumModeOf(file, oldKey) == kIncrementalVacuum);

    sqlite3_int64 heapBefore = 0;
    sqlite3_int64 heapPeak = 0;
    CHECK(sqlite3_status64(SQLITE_STATUS_MEMORY_USED, &heapBefore, &heapPeak, 1) == SQLITE_OK);
    accountkey::rekey(file, "old pass", "new pass");
    sqlite3_int64 heapAfter = 0;
    CHECK(sqlite3_status64(SQLITE_STATUS_MEMORY_USED, &heapAfter, &heapPeak, 0) == SQLITE_OK);
    CHECK(heapPeak > heapBefore);
    CHECK(heapPeak - heapBefore < databaseBytes / kHeapShareOfDatabase);

    CHECK(openKeyed(file, oldKey) == nullptr);
    accountkey::forget(file);
    CHECK_THROWS(AccountDb(file, "old pass"));
    CHECK(*AccountDb(file, "new pass").get("row-" + std::to_string(kLargeRows - 1)) == lastRow);
    CHECK(*AccountDb(file, "new pass").get("row-0") != lastRow);
    CHECK(vacuumModeOf(file, accountkey::keyFor(file, "new pass")) == kIncrementalVacuum);
    for (const char* const suffix : {"-rekey", "-rekey-journal"}) {
        CHECK(!fs::exists(suffixed(file, suffix)));
        CHECK(!fs::exists(suffixed(accountkey::sidecarFor(file), suffix)));
    }
}

void checkRefusedWhileOpen(const fs::path& dir)
{
    const fs::path file = dir / "busy.db";
    {
        AccountDb db(file, "pass");
        db.putText("kept", "yes");
    }
    {
        TranscriptStore held;
        CHECK(held.open(file, "pass"));
        CHECK_THROWS(accountkey::rekey(file, "pass", "other"));
    }
    accountkey::forget(file);
    CHECK(AccountDb(file, "pass").text("kept") == "yes");
    CHECK_THROWS(accountkey::rekey(file, "not the pass", "other"));
    accountkey::forget(file);
    CHECK(AccountDb(file, "pass").text("kept") == "yes");
}

void checkInterrupted(const fs::path& dir)
{
    const fs::path file = dir / "cut.db";
    const fs::path sidecar = accountkey::sidecarFor(file);
    {
        AccountDb db(file, "old pass");
        db.putText("kept", "yes");
    }
    accountkey::forget(file);

    writePrivateFile(suffixed(file, "-rekey"), "half a database");
    writePrivateFile(suffixed(file, "-rekey-journal"), "its journal");
    writePrivateFile(suffixed(sidecar, "-rekey"), readFileText(sidecar));
    CHECK(AccountDb(file, "old pass").text("kept") == "yes");
    CHECK(!fs::exists(suffixed(file, "-rekey")));
    CHECK(!fs::exists(suffixed(file, "-rekey-journal")));
    CHECK(!fs::exists(suffixed(sidecar, "-rekey")));
    accountkey::forget(file);

    const std::string oldSidecar = readFileText(sidecar);
    accountkey::rekey(file, "old pass", "new pass");
    accountkey::forget(file);
    fs::rename(sidecar, suffixed(sidecar, "-rekey"));
    writePrivateFile(sidecar, oldSidecar);
    CHECK(AccountDb(file, "new pass").text("kept") == "yes");
    CHECK(!fs::exists(suffixed(sidecar, "-rekey")));
    accountkey::forget(file);
    CHECK_THROWS(AccountDb(file, "old pass"));
    accountkey::forget(file);
    CHECK(AccountDb(file, "new pass").text("kept") == "yes");
}

template <typename Error, typename Work>
bool refusedWith(const Work& work)
{
    try {
        work();
    } catch (const Error&) {
        return true;
    }
    return false;
}

void checkReservedPassphrase(const fs::path& dir)
{
    CHECK(accountkey::isReservedPassphrase(accountkey::kOpenSecret));
    CHECK(!accountkey::isReservedPassphrase(""));
    const fs::path refused = dir / "reserved.db";
    CHECK(refusedWith<accountkey::ReservedPassphrase>(
        [&refused]() { static_cast<void>(AccountDb(refused, accountkey::kOpenSecret)); }));
    CHECK(!fs::exists(accountkey::sidecarFor(refused)));

    const fs::path file = dir / "kept.db";
    {
        AccountDb db(file, "pass");
        db.putText("kept", "yes");
    }
    CHECK(refusedWith<accountkey::ReservedPassphrase>(
        [&file]() { accountkey::rekey(file, "pass", accountkey::kOpenSecret); }));
    accountkey::forget(file);
    CHECK(AccountDb(file, "pass").text("kept") == "yes");

    AccountManager manager(dir / "reserved-accounts");
    CHECK(refusedWith<accountkey::ReservedPassphrase>([&manager]() {
        static_cast<void>(manager.create("Reserved", AccountKind::eUser, accountkey::kOpenSecret));
    }));
}

void checkSessionPassphrase(const fs::path& dir)
{
    AccountManager manager(dir / "accounts");
    const AccountInfo made = manager.create("Rekeyed", AccountKind::eUser, "first");
    const fs::path file = manager.fileFor(made.id);
    Session::changePassphrase(file, "first", "second");
    accountkey::forget(file);
    CHECK_THROWS(manager.open(made.id, "first"));
    CHECK(manager.open(made.id, "second")->fingerprint() == made.fingerprint);
    Session::changePassphrase(file, "second", "");
    accountkey::forget(file);
    CHECK(manager.open(made.id)->fingerprint() == made.fingerprint);
    for (const AccountInfo& listed : manager.list()) {
        CHECK(!listed.encrypted);
        CHECK(listed.fingerprint == made.fingerprint);
    }
}

void checkLockedListedQuietly(const fs::path& dir)
{
    AccountManager manager(dir / "locked-list");
    const AccountInfo made = manager.create("Locked", AccountKind::eUser, "secret");
    accountkey::forget(manager.fileFor(made.id));
    std::vector<std::string> lines;
    log::setTap([&lines](log::Level, std::string_view, const std::string_view message) {
        lines.emplace_back(message);
    });
    const std::vector<AccountInfo> listed = manager.list();
    CHECK(manager.count() == 1);
    log::setTap({});
    CHECK(listed.size() == 1);
    CHECK(listed.front().encrypted);
    CHECK(lines.empty());
}

void checkUnreadableNotListed(const fs::path& dir)
{
    AccountManager manager(dir / "unreadable-list");
    const AccountInfo kept = manager.create("Kept", AccountKind::eUser, "");
    const AccountInfo broken = manager.create("Broken", AccountKind::eUser, "");
    {
        AccountDb db(manager.fileFor(broken.id), "");
        db.put("device-cert", Bytes{1, 2, 3});
    }
    const std::vector<AccountInfo> listed = manager.list();
    CHECK(listed.size() == 1);
    CHECK(listed.front().id == kept.id);
    CHECK(manager.count() == 2);
    CHECK(fs::exists(manager.fileFor(broken.id)));
}

std::string secondPemLine(const std::string& pem)
{
    std::istringstream lines(pem);
    std::string line;
    std::getline(lines, line);
    std::getline(lines, line);
    return line;
}

void checkEndedEpochErased(const fs::path& dir)
{
    AccountManager manager(dir / "erasure");
    const AccountInfo made = manager.create("Erased", AccountKind::eUser, "pw");
    const fs::path file = manager.fileFor(made.id);
    TranscriptStore history;
    CHECK(history.open(file, "pw"));

    const std::int64_t now = systemUtcSeconds();
    const EpochNumber ended = epochAt(now) - kMonthsAgo;
    CHECK(now >= epochEnd(ended) + kEpochKeptAfterEndSeconds);
    const Key endedKey = Key::generateSealing();
    const std::string needle = secondPemLine(endedKey.privatePem());
    {
        AccountDb db(file, "pw");
        const nlohmann::json held = db.document("epochs");
        EpochRing ring;
        ring.addAll(held);
        CHECK(ring.add(ended, 0, held.at(0).at("by").get<std::string>(),
            Key::fromPrivatePem(endedKey.privatePem())));
        db.putText("epochs", ring.toJson().dump());
    }
    const SecretBytes key = accountkey::keyFor(file, "pw");
    CHECK(filesHold(file, key, needle));

    const std::unique_ptr<Session> session = manager.open(made.id, "pw");
    EpochRing kept;
    kept.addAll(AccountDb(file, "pw").document("epochs"));
    CHECK(!kept.holds(ended));
    CHECK(kept.holds(epochAt(now)));
    CHECK(fs::file_size(suffixed(file, "-wal")) == 0);
    CHECK(!filesHold(file, key, needle));
}

void checkBundleHoldsActiveKeysOnly(const fs::path& dir)
{
    AccountManager manager(dir / "bundle");
    const AccountInfo made = manager.create("Bundled", AccountKind::eUser, "pw");
    const fs::path file = manager.fileFor(made.id);
    const std::int64_t now = systemUtcSeconds();
    const EpochNumber current = epochAt(now);
    std::string needle;
    for (const nlohmann::json& held : AccountDb(file, "pw").document("epochs")) {
        if (held.at("n").get<EpochNumber>() == current) {
            needle = secondPemLine(held.at("pem").get<std::string>());
        }
    }
    CHECK(!needle.empty());

    const std::unique_ptr<Session> session = manager.open(made.id, "pw");
    const std::int64_t later = epochEnd(current) + kEpochKeptAfterEndSeconds;
    session->setEpochClock([later]() { return later; });
    const Bytes sealed = session->exportAccountBytes("bundle-pw");
    const SecretBytes opened = accountkey::openBackup(sealed, "bundle-pw");
    const Bytes& plain = opened.bytes();
    const nlohmann::json bundle = nlohmann::json::parse(plain.begin(), plain.end());
    for (const nlohmann::json& carried : bundle.at("epochs")) {
        CHECK(later < epochEnd(carried.at("n").get<EpochNumber>()) + kEpochKeptAfterEndSeconds);
    }
    CHECK(std::string(plain.begin(), plain.end()).find(needle) == std::string::npos);
    EpochRing kept;
    kept.addAll(AccountDb(file, "pw").document("epochs"));
    CHECK(!kept.holds(current));
    CHECK(!filesHold(file, accountkey::keyFor(file, "pw"), needle));

    const fs::path imported = dir / "bundle" / "imported.db";
    Session::importAccountBytes(sealed, imported, "bundle-pw", "imported pw");
    CHECK(vacuumModeOf(imported, accountkey::keyFor(imported, "imported pw"))
        == kIncrementalVacuum);
}

StoredMessage textLine(const std::string& peer, const std::string& text)
{
    StoredMessage message;
    message.peer = peer;
    message.type = "text";
    message.e2eId = toHex(randomBytes(kMessageIdBytes));
    message.text = text;
    return message;
}

void checkDeletedMessagesLeaveNoTrace(const fs::path& dir)
{
    const fs::path file = dir / "deleted.db";
    {
        AccountDb account(file, "pw");
        account.putText("kept", "yes");
    }
    const SecretBytes key = accountkey::keyFor(file, "pw");
    TranscriptStore store;
    CHECK(store.open(file, "pw"));
    TranscriptStore reader;
    CHECK(reader.open(file, "pw"));
    const std::string one = "the first secret line " + toHex(randomBytes(kMessageIdBytes));
    const std::string two = "the second secret line " + toHex(randomBytes(kMessageIdBytes));
    const std::string three = "the third secret line " + toHex(randomBytes(kMessageIdBytes));
    const std::int64_t first = store.append(textLine("alice", one));
    const std::int64_t second = store.append(textLine("bob", two));
    CHECK(store.setChatTimer("carol", kSecondsPerHour));
    StoredMessage timed = textLine("carol", three);
    timed.outgoing = true;
    timed.ts = kLongAgoMs;
    timed.orderKey = kLongAgoMs;
    const std::int64_t third = store.append(timed);
    CHECK(first != 0 && second != 0 && third != 0);
    CHECK(filesHold(file, key, one) && filesHold(file, key, two) && filesHold(file, key, three));

    const std::string edited = "the edited line " + toHex(randomBytes(kMessageIdBytes));
    const std::int64_t fourth = store.append(textLine("dave", edited));
    CHECK(fourth != 0);
    CHECK(filesHold(file, key, edited));
    CHECK(store.editContent(fourth, "what it says now", {}));
    CHECK(fs::file_size(suffixed(file, "-wal")) == 0);
    CHECK(!filesHold(file, key, edited));
    CHECK(filesHold(file, key, "what it says now"));

    CHECK(store.removeById(first));
    CHECK(fs::file_size(suffixed(file, "-wal")) == 0);
    CHECK(!filesHold(file, key, one));
    CHECK(filesHold(file, key, two));

    CHECK(store.clearPeer("bob"));
    CHECK(fs::file_size(suffixed(file, "-wal")) == 0);
    CHECK(!filesHold(file, key, two));

    const std::optional<std::vector<RemovedRow>> expired = store.removeExpired(kLongAgoMs + 2 * kSecondsPerHour * kMsPerSecond);
    CHECK(expired.has_value() && expired->size() == 1);
    CHECK(expired->front().id == third && expired->front().peer == "carol");
    CHECK(fs::file_size(suffixed(file, "-wal")) == 0);
    CHECK(!filesHold(file, key, three));
    CHECK(AccountDb(file, "pw").text("kept") == "yes");

    const std::string padding(kLinePaddingBytes, '.');
    const std::string erased = "an erased secret " + toHex(randomBytes(kMessageIdBytes));
    const std::string survivor = "a surviving line " + toHex(randomBytes(kMessageIdBytes));
    for (int at = 0; at < kErasedLines; ++at) {
        CHECK(store.append(textLine("erin", erased + std::to_string(at) + padding)) != 0);
    }
    CHECK(store.append(textLine("frank", survivor)) != 0);
    CHECK(store.clearPeer("erin"));
    CHECK(store.footprint().freeBytes > 0);
    const std::uintmax_t loose = fs::file_size(file);
    std::string reason;
    CHECK(store.compact(reason));
    CHECK(store.footprint().freeBytes == 0);
    CHECK(fs::file_size(file) < loose);
    CHECK(fs::file_size(suffixed(file, "-wal")) == 0);
    CHECK(!filesHold(file, key, erased));
    CHECK(filesHold(file, key, survivor));
}

}  // namespace

int main()
try {
    const testutil::ScratchDir scratch("account-key");
    const fs::path& dir = scratch.path();
    checkBackup();
    checkLargeRekey(dir);
    checkRefusedWhileOpen(dir);
    checkInterrupted(dir);
    checkSessionPassphrase(dir);
    checkLockedListedQuietly(dir);
    checkUnreadableNotListed(dir);
    checkReservedPassphrase(dir);
    checkEndedEpochErased(dir);
    checkBundleHoldsActiveKeysOnly(dir);
    checkDeletedMessagesLeaveNoTrace(dir);
    return 0;
} catch (...) {
    return testutil::failed();
}
