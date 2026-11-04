// Bazarish project (c) 2026
#include "AccountDb.hpp"
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
    const fs::path root = fs::temp_directory_path() / "bazarish-test-transcript";
    fs::remove_all(root);
    fs::create_directories(root);
    const fs::path file = root / "account.db";

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

    const DatabaseFootprint before = store.footprint();
    CHECK(before.freeBytes >= static_cast<std::int64_t>(kPictureBytes / 2));
    std::string reason;
    CHECK(store.rebuild(reason));
    const DatabaseFootprint after = store.footprint();
    CHECK(after.freeBytes == 0);
    CHECK(after.fileBytes + static_cast<std::int64_t>(kPictureBytes / 2) < before.fileBytes);
    CHECK(account.has(kPictureKeyPrefix + std::string("o1")));

    store.close();
    fs::remove_all(root);
    std::fprintf(stderr, "TestTranscriptCore passed\n");
    return 0;
}
