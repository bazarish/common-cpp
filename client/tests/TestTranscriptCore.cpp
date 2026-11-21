// Bazarish project (c) 2026
#include "AccountDb.hpp"
#include "AccountKey.hpp"
#include "KeyedDatabase.hpp"
#include "MediaKeys.hpp"
#include "TranscriptDb.hpp"

#include "TestUtil.hpp"

#include <bazarish/Clock.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace fs = std::filesystem;

namespace {

constexpr std::size_t kPictureBytes = 2 * 1024 * 1024;
constexpr const char* kPeer = "peer";
constexpr const char* kOther = "other";
constexpr const char* kSharer = "sharer";
constexpr std::size_t kSharedPictureBytes = 16;
constexpr std::size_t kNamelessPictureBytes = 8;
constexpr const char* kThisDevice = "abcd2efgh3";
constexpr const char* kHostDevice = "hostdev234";
constexpr std::size_t kLooseMediaBytes = 1024 * 1024;
constexpr int kLooseMedia = 96;
// Well under the 5 s busy timeout; a whole-file VACUUM of this file holds a writer for seconds.
constexpr std::chrono::milliseconds kLongestWriteWait{1000};
constexpr std::chrono::milliseconds kBetweenWrites{5};
constexpr std::size_t kLoggedMediaBytes = 64 * 1024;
constexpr int kLoggedMedia = 96;
// Pointer-map pages leave with the file's tail as well.
constexpr std::int64_t kEstimateSlackDivisor = 100;

StoredMessage line(const std::string& peer, const std::string& type, const std::string& e2eId)
{
    StoredMessage message;
    message.peer = peer;
    message.type = type;
    message.e2eId = e2eId;
    message.text = type == "text" ? "hello" : "";
    return message;
}

void checkEstimateMatchesCompaction(const fs::path& root)
{
    const fs::path file = root / "logged.db";
    AccountDb account(file, "secret");
    TranscriptStore store;
    CHECK(store.open(file, "secret"));
    for (int at = 0; at < kLoggedMedia; ++at) {
        account.put(kPictureKeyPrefix + std::to_string(at), Bytes(kLoggedMediaBytes, 0x55));
    }
    for (int at = 0; at < kLoggedMedia; at += 2) {
        account.erase(kPictureKeyPrefix + std::to_string(at));
    }
    fs::path wal = file;
    wal += "-wal";
    CHECK(fs::file_size(wal) > 0);
    const DatabaseFootprint before = store.footprint();
    std::string reason;
    CHECK(store.compact(reason));
    const DatabaseFootprint after = store.footprint();
    const std::int64_t freed = before.fileBytes - after.fileBytes;
    CHECK(before.freeBytes <= freed);
    CHECK(freed - before.freeBytes <= freed / kEstimateSlackDivisor);
    CHECK(after.freeBytes == 0);
}

void checkWritesGoOnDuringCompaction(const fs::path& root)
{
    const fs::path file = root / "loose.db";
    AccountDb account(file, "secret");
    TranscriptStore store;
    CHECK(store.open(file, "secret"));
    for (int at = 0; at < kLooseMedia; ++at) {
        account.put(kPictureKeyPrefix + std::to_string(at), Bytes(kLooseMediaBytes, 0x33));
        account.put(kVoiceKeyPrefix + std::to_string(at), Bytes(kLooseMediaBytes, 0x44));
        CHECK(store.append(line(kOther, "text", "kept" + std::to_string(at))) != 0);
    }
    for (int at = 0; at < kLooseMedia; ++at) {
        account.erase(kPictureKeyPrefix + std::to_string(at));
    }
    account.dropOverwritten();
    const DatabaseFootprint before = store.footprint();
    CHECK(before.freeBytes >= static_cast<std::int64_t>(kLooseMediaBytes) * kLooseMedia);

    std::atomic<bool> compacting{true};
    bool compacted = false;
    std::string reason;
    std::thread compactor([&]() {
        TranscriptStore own;
        CHECK(own.open(file, "secret"));
        compacted = own.compact(reason);
        compacting = false;
    });
    int writes = 0;
    std::chrono::steady_clock::duration longest{};
    while (compacting) {
        const auto started = std::chrono::steady_clock::now();
        account.putText("tick", std::to_string(writes));
        longest = std::max(longest, std::chrono::steady_clock::now() - started);
        ++writes;
        std::this_thread::sleep_for(kBetweenWrites);
    }
    compactor.join();
    CHECK(compacted);
    CHECK(writes > 1);
    CHECK(longest < kLongestWriteWait);
    account.dropOverwritten();
    const DatabaseFootprint after = store.footprint();
    CHECK(after.freeBytes == 0);
    CHECK(after.fileBytes + static_cast<std::int64_t>(kLooseMediaBytes) * kLooseMedia / 2
        < before.fileBytes);
    CHECK(store.latestMessages(kOther, kLooseMedia).size()
        == static_cast<std::size_t>(kLooseMedia));
    CHECK(account.text("tick") == std::to_string(writes - 1));
}

void checkChatList(const fs::path& root)
{
    const fs::path file = root / "chats.db";
    AccountDb account(file, "secret");
    TranscriptStore store;
    CHECK(store.open(file, "secret"));
    CHECK(store.conversationPeers().empty());
    CHECK(store.unreadTotal() == 0);
    CHECK(store.chatWeights().empty());

    const auto put = [&store](const std::string& peer, const std::string& type,
                         const std::string& e2eId, const std::int64_t at, const bool outgoing) {
        StoredMessage message = line(peer, type, e2eId);
        message.ts = at;
        message.orderKey = at;
        message.outgoing = outgoing;
        const std::int64_t id = store.append(message);
        CHECK(id != 0);
        return id;
    };
    const std::int64_t read = put(kPeer, "text", "p1", 100, false);
    put(kOther, "text", "o1", 150, false);
    put(kPeer, "image", "p2", 300, false);
    put(kOther, "text", "o2", 120, true);
    put(kPeer, "text", "p3", 200, false);
    put(kPeer, "system", "", 400, false);
    put(kPeer, "reaction", "p4", 500, false);
    put(kSharer, "text", "p2", 50, true);
    CHECK(store.setLastReadId(kPeer, read));
    account.put(kPictureKeyPrefix + std::string("p2"), Bytes(kSharedPictureBytes, 0x11));
    account.put(kPictureKeyPrefix, Bytes(kNamelessPictureBytes, 0x22));

    CHECK((store.conversationPeers() == std::vector<std::string>{kOther, kPeer, kSharer}));
    CHECK(store.unreadTotal() == 4);
    const std::vector<ChatWeight> weights = store.chatWeights();
    CHECK(weights.size() == 3);
    for (const ChatWeight& weight : weights) {
        const bool holdsPicture = weight.peer == kPeer || weight.peer == kSharer;
        CHECK(weight.mediaCount == (holdsPicture ? 1 : 0));
        CHECK(weight.mediaBytes
            == (holdsPicture ? static_cast<std::int64_t>(kSharedPictureBytes) : 0));
    }
}

void checkExpiryStamps(const fs::path& root)
{
    const fs::path file = root / "expiries.db";
    AccountDb account(file, "secret");
    TranscriptStore store;
    CHECK(store.open(file, "secret"));
    std::vector<std::int64_t> told;
    store.onExpiryStamped([&told](const std::int64_t atMs) { told.push_back(atMs); });
    const auto put = [&store](
                         const std::string& e2eId, const std::int64_t at, const bool outgoing) {
        StoredMessage message = line(kPeer, "text", e2eId);
        message.ts = at;
        message.orderKey = at;
        message.outgoing = outgoing;
        const std::int64_t id = store.append(message);
        CHECK(id != 0);
        return id;
    };
    constexpr std::int64_t kSentAt = 1000;

    put("before", kSentAt, true);
    CHECK(told.empty());
    CHECK(!store.nextExpiryAt().has_value());

    CHECK(store.setChatTimer(kPeer, kSecondsPerHour));
    put("sent", kSentAt, true);
    const std::int64_t sentExpires = kSentAt + kSecondsPerHour * kMillisPerSecond;
    CHECK((told == std::vector<std::int64_t>{sentExpires}));
    CHECK(store.nextExpiryAt() == sentExpires);

    const std::int64_t incoming = put("came", kSentAt, false);
    CHECK(told.size() == 1);
    const std::int64_t readFrom = nowMillis() + kSecondsPerHour * kMillisPerSecond;
    CHECK(store.setLastReadId(kPeer, incoming));
    const std::int64_t readTo = nowMillis() + kSecondsPerHour * kMillisPerSecond;
    CHECK(told.size() == 2);
    CHECK(told.back() >= readFrom && told.back() <= readTo);
    CHECK(store.setLastReadId(kPeer, incoming));
    CHECK(told.size() == 2);
    CHECK(store.nextExpiryAt() == sentExpires);
}

}  // namespace

int main()
try {
    const testutil::ScratchDir scratch("transcript");
    const fs::path& root = scratch.path();
    const fs::path file = root / "account.db";

    {
        AccountDb account(file, "secret");
        TranscriptStore store;
        CHECK(store.open(file, "secret"));

        CHECK(store.append(line(kPeer, "image", "pppppppppp")) != 0);
        account.put(kPictureKeyPrefix + std::string("pppppppppp"), Bytes(kPictureBytes, 0x5a));
        const std::int64_t voice = store.append(line(kPeer, "audio", "v1"));
        CHECK(voice != 0);
        account.put(kVoiceKeyPrefix + std::string("v1"), Bytes(16, 0x11));
        CHECK(store.append(line(kOther, "image", "o1")) != 0);
        account.put(kPictureKeyPrefix + std::string("o1"), Bytes(16, 0x22));
        CHECK(store.setReaction(kPeer, "v1", "someone", "+1"));

        CHECK(store.removeById(voice));
        CHECK(!account.has(kVoiceKeyPrefix + std::string("v1")));
        CHECK(store.reactionsFor(kPeer, "v1").empty());
        CHECK(account.has(kPictureKeyPrefix + std::string("pppppppppp")));

        CHECK(store.setChatTimer(kPeer, 60));
        CHECK(store.clearPeer(kPeer));
        CHECK(store.latestMessages(kPeer, 10).empty());
        CHECK(!account.has(kPictureKeyPrefix + std::string("pppppppppp")));
        CHECK(store.chatTimer(kPeer) == 60);
        CHECK(account.has(kPictureKeyPrefix + std::string("o1")));
        CHECK(store.latestMessages(kOther, 10).size() == 1);

        StoredMessage sent = line(kOther, "text", "s1");
        sent.outgoing = true;
        sent.status = static_cast<int>(DeliveryState::eDelivering);
        sent.device = kThisDevice;
        const std::int64_t sentId = store.append(sent);
        CHECK(store.messageById(sentId).device == kThisDevice);
        StoredMessage post = line(kOther, "text", "g1");
        post.device = kHostDevice;
        post.author = kPeer;
        const StoredMessage relayed = store.messageById(store.append(post));
        CHECK(relayed.device == kHostDevice);
        CHECK(relayed.author == kPeer);
        CHECK(!relayed.fromHost);
        const auto statusOf = [&store](const std::int64_t id) { return store.messageById(id).status; };
        CHECK(store.advanceStatus(sentId, static_cast<int>(DeliveryState::eDelivered)) == true);
        CHECK(store.advanceStatus(sentId, static_cast<int>(DeliveryState::eAtRecipientServer)) == false);
        CHECK(statusOf(sentId) == static_cast<int>(DeliveryState::eDelivered));
        CHECK(store.advanceStatus(sentId, static_cast<int>(DeliveryState::eFailed)) == true);
        CHECK(statusOf(sentId) == static_cast<int>(DeliveryState::eFailed));

        const Bytes shot(kPictureBytes / 4, 0x5c);
        CHECK(store.keepMedia(kPictureKeyPrefix + std::string("unsent"), shot));
        CHECK(store.media(kPictureKeyPrefix + std::string("unsent")) == shot);
        CHECK(store.keepMedia(kPictureKeyPrefix + std::string("unsent"), Bytes{1, 2, 3}));
        CHECK(store.media(kPictureKeyPrefix + std::string("unsent")) == shot);

        const DatabaseFootprint before = store.footprint();
        CHECK(before.freeBytes >= static_cast<std::int64_t>(kPictureBytes / 2));
        std::string reason;
        CHECK(store.compact(reason));
        const DatabaseFootprint after = store.footprint();
        CHECK(after.freeBytes == 0);
        CHECK(after.fileBytes + static_cast<std::int64_t>(kPictureBytes / 2) < before.fileBytes);
        CHECK(account.has(kPictureKeyPrefix + std::string("o1")));

        const fs::path copy = root / "copy.db";
        copyKeyedDatabase(file, copy, accountkey::keyFor(file, "secret"));
        {
            TranscriptReader reader;
            CHECK(reader.open(copy, accountkey::keyFor(file, "secret")));
            CHECK(reader.latestMessages(kOther, 10).size() == 3);
            CHECK(!reader.media(kPictureKeyPrefix + std::string("o1")).empty());
        }
        store.close();
    }
    checkEstimateMatchesCompaction(root);
    checkWritesGoOnDuringCompaction(root);
    checkChatList(root);
    checkExpiryStamps(root);
    std::fprintf(stderr, "TestTranscriptCore passed\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
