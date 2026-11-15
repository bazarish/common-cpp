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
#include <bazarish/PrivateFile.hpp>

#include "TestUtil.hpp"

#include <openssl/evp.h>
#include <sqlcipher/sqlite3.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

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

// SQLCipher 4 defaults: 4096-byte pages, each ending in a 16-byte IV and a 64-byte HMAC.
constexpr std::size_t kPageBytes = 4096;
constexpr std::size_t kReserveBytes = 80;
constexpr std::size_t kSaltBytes = 16;
// SQLite's WAL format: a 32-byte file header, then a 24-byte header before each page.
constexpr std::size_t kWalHeaderBytes = 32;
constexpr std::size_t kFrameHeaderBytes = 24;
constexpr EpochNumber kMonthsAgo = 6;

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

Bytes decryptedPage(const Bytes& key, const unsigned char* const page, const bool first)
{
    const std::size_t from = first ? kSaltBytes : 0;
    const std::size_t size = kPageBytes - kReserveBytes - from;
    const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    Bytes plain(size);
    int written = 0;
    CHECK(ctx != nullptr);
    CHECK(EVP_DecryptInit_ex(
              ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), page + kPageBytes - kReserveBytes)
        == 1);
    CHECK(EVP_CIPHER_CTX_set_padding(ctx.get(), 0) == 1);
    CHECK(EVP_DecryptUpdate(ctx.get(), plain.data(), &written, page + from, static_cast<int>(size))
        == 1);
    return plain;
}

bool pageHolds(const Bytes& key, const unsigned char* const page, const bool first,
    const std::string& needle)
{
    const Bytes plain = decryptedPage(key, page, first);
    return std::string(plain.begin(), plain.end()).find(needle) != std::string::npos;
}

// Reads every page the files hold, live or freed, current or superseded.
bool filesHold(const fs::path& database, const Bytes& key, const std::string& needle)
{
    const Bytes pages = readFileBytes(database);
    for (std::size_t at = 0; at + kPageBytes <= pages.size(); at += kPageBytes) {
        if (pageHolds(key, pages.data() + at, at == 0, needle)) {
            return true;
        }
    }
    const fs::path wal = suffixed(database, "-wal");
    if (!fs::exists(wal)) {
        return false;
    }
    const Bytes log = readFileBytes(wal);
    for (std::size_t at = kWalHeaderBytes; at + kFrameHeaderBytes + kPageBytes <= log.size();
         at += kFrameHeaderBytes + kPageBytes) {
        const std::uint32_t pageNumber = (static_cast<std::uint32_t>(log[at]) << 24)
            | (static_cast<std::uint32_t>(log[at + 1]) << 16)
            | (static_cast<std::uint32_t>(log[at + 2]) << 8) | log[at + 3];
        if (pageHolds(key, log.data() + at + kFrameHeaderBytes, pageNumber == 1, needle)) {
            return true;
        }
    }
    return false;
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
    const Bytes oldKey = accountkey::keyFor(file, "old pass");
    const Bytes lastRow = *AccountDb(file, "old pass").get("row-" + std::to_string(kLargeRows - 1));
    const std::int64_t databaseBytes = static_cast<std::int64_t>(fs::file_size(file));
    CHECK(databaseBytes > static_cast<std::int64_t>(kRowBytes * kLargeRows));

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
    const Bytes key = accountkey::keyFor(file, "pw");
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
}

}  // namespace

int main()
{
    const fs::path dir = testutil::freshDir("account-key");
    checkBackup();
    checkLargeRekey(dir);
    checkRefusedWhileOpen(dir);
    checkInterrupted(dir);
    checkSessionPassphrase(dir);
    checkReservedPassphrase(dir);
    checkEndedEpochErased(dir);
    checkBundleHoldsActiveKeysOnly(dir);
    fs::remove_all(dir);
    return 0;
}
