// Bazarish project (c) 2026
#include "AccountDb.hpp"
#include "AccountKey.hpp"
#include "KeyedDatabase.hpp"
#include "MediaKeys.hpp"
#include "TranscriptDb.hpp"

#include "TestUtil.hpp"

#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

namespace fs = std::filesystem;

namespace {

constexpr std::size_t kPictureBytes = 2 * 1024 * 1024;
constexpr const char* kPeer = "peer";
constexpr const char* kOther = "other";

StoredMessage line(const std::string& peer, const std::string& type, const std::string& e2eId)
{
    StoredMessage message;
    message.peer = peer;
    message.type = type;
    message.e2eId = e2eId;
    message.text = type == "text" ? "hello" : "";
    return message;
}

}  // namespace

int main()
{
    const fs::path root = testutil::freshDir("transcript");
    const fs::path file = root / "account.db";

    {
        AccountDb account(file, "secret");
        TranscriptStore store;
        CHECK(store.open(file, "secret"));

        CHECK(store.append(line(kPeer, "image", "p1")) != 0);
        account.put(kPictureKeyPrefix + std::string("p1"), Bytes(kPictureBytes, 0x5a));
        const std::int64_t voice = store.append(line(kPeer, "audio", "v1"));
        CHECK(voice != 0);
        account.put(kVoiceKeyPrefix + std::string("v1"), Bytes(16, 0x11));
        CHECK(store.append(line(kOther, "image", "o1")) != 0);
        account.put(kPictureKeyPrefix + std::string("o1"), Bytes(16, 0x22));
        CHECK(store.setReaction(kPeer, "v1", "someone", "+1"));

        CHECK(store.removeById(voice));
        CHECK(!account.has(kVoiceKeyPrefix + std::string("v1")));
        CHECK(store.reactionsFor(kPeer, "v1").empty());
        CHECK(account.has(kPictureKeyPrefix + std::string("p1")));

        CHECK(store.setChatTimer(kPeer, 60));
        CHECK(store.clearPeer(kPeer));
        CHECK(store.latestMessages(kPeer, 10).empty());
        CHECK(!account.has(kPictureKeyPrefix + std::string("p1")));
        CHECK(store.chatTimer(kPeer) == 60);
        CHECK(account.has(kPictureKeyPrefix + std::string("o1")));
        CHECK(store.latestMessages(kOther, 10).size() == 1);

        StoredMessage sent = line(kOther, "text", "s1");
        sent.outgoing = true;
        sent.status = static_cast<int>(DeliveryState::eDelivering);
        const std::int64_t sentId = store.append(sent);
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
        CHECK(store.rebuild(reason));
        const DatabaseFootprint after = store.footprint();
        CHECK(after.freeBytes == 0);
        CHECK(after.fileBytes + static_cast<std::int64_t>(kPictureBytes / 2) < before.fileBytes);
        CHECK(account.has(kPictureKeyPrefix + std::string("o1")));

        const fs::path copy = root / "copy.db";
        copyKeyedDatabase(file, copy, accountkey::keyFor(file, "secret"));
        {
            TranscriptReader reader;
            CHECK(reader.open(copy, accountkey::keyFor(file, "secret")));
            CHECK(reader.latestMessages(kOther, 10).size() == 2);
            CHECK(!reader.media(kPictureKeyPrefix + std::string("o1")).empty());
        }
        store.close();
    }
    fs::remove_all(root);
    std::fprintf(stderr, "TestTranscriptCore passed\n");
    return 0;
}
