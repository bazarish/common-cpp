// Bazarish project (c) 2026
#include "AccountDb.hpp"
#include "MessageTypes.hpp"
#include "TranscriptIngest.hpp"

#include "TestUtil.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

namespace fs = std::filesystem;

namespace {

constexpr const char* kOwn = "own";
constexpr const char* kPeer = "peer";
constexpr std::int64_t kDeliveryLagMs = 3000;

class Notes final : public IngestNotes {
public:
    std::string chatCleared(bool, const std::string&) const override { return "cleared"; }
    std::string chatTimer(std::int64_t, bool, const std::string&) const override { return "timer"; }
    std::string contactAccepted(const std::string&) const override { return "accepted"; }
    std::string unsupported(const std::string&, const Bytes&) const override { return "unsupported"; }
};

std::int64_t millisNow()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

IncomingMessage incoming(const std::string& type, const std::string& e2eId, const std::int64_t sentAt)
{
    IncomingMessage message;
    message.contentType = type;
    message.fromFingerprint = kPeer;
    message.e2eId = e2eId;
    message.sentAt = sentAt;
    message.text = type == kTypeText ? "Choose a language" : "";
    return message;
}

}  // namespace

int main()
{
    const fs::path root = testutil::freshDir("ingest");
    const fs::path file = root / "account.db";
    {
        AccountDb account(file, "secret");
        TranscriptStore store;
        CHECK(store.open(file, "secret"));
        const Notes notes;
        IngestListener listener;
        TranscriptIngest ingest(store, []() { return std::string(kOwn); }, notes, listener);

        const std::int64_t composedAt = millisNow() - kDeliveryLagMs;
        CHECK(ingest.takeIn(incoming(kTypeContactAccept, "accept", composedAt)));
        CHECK(ingest.takeIn(incoming(kTypeText, "menu", composedAt + 1)));

        std::int64_t acceptKey = 0;
        std::int64_t menuKey = 0;
        for (const StoredMessage& row : store.latestMessages(kPeer, 10)) {
            if (row.e2eId == "accept") {
                acceptKey = row.orderKey;
            } else if (row.e2eId == "menu") {
                menuKey = row.orderKey;
            }
        }
        CHECK(acceptKey != 0 && menuKey != 0);
        CHECK(acceptKey < menuKey);
        store.close();
    }
    fs::remove_all(root);
    std::fprintf(stderr, "TestTranscriptIngest passed\n");
    return 0;
}
