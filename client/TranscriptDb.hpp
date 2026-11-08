// Bazarish project (c) 2026
#pragma once

#include "KeyedDatabase.hpp"

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace bazarish::client {

// Both front-ends read these numbers from the file.
enum class DeliveryState : int {
    ePreparing = 0,
    eDelivering = 1,
    eAtRecipientServer = 2,
    eDelivered = 3,
    eFailed = 4,
    eReceived = 5,
};

struct StoredMessage {
    std::int64_t id = 0;
    std::string peer;
    bool outgoing = false;
    std::string type;
    std::string e2eId;
    std::string text;
    std::string attName;
    std::string attMime;
    std::int64_t attSize = 0;
    std::int64_t attDurationMs = 0;
    std::string attWave;
    std::string attRef;
    std::string attSrcPath;
    std::string savedPath;
    bool hasPicture = false;
    std::string keyboard;
    std::string replyTo;
    bool edited = false;
    bool forwarded = false;
    std::int64_t ts = 0;
    std::int64_t orderKey = 0;
    int status = 0;
    std::string author;
    bool contactable = false;
    bool fromHost = false;
};

struct SearchableRow {
    std::int64_t id = 0;
    std::int64_t ts = 0;
    std::string text;
    std::string attName;
    std::string type;
    bool outgoing = false;
};

struct Reaction {
    std::string reactor;
    std::string emoji;
};

struct GroupState {
    std::string kind;
    std::int64_t members = 0;
    bool write = false;
    bool admin = false;
    std::int64_t at = 0;
};

struct ChatWeight {
    std::string peer;
    std::int64_t messages = 0;
    std::int64_t rowBytes = 0;
    std::int64_t mediaBytes = 0;
    std::int64_t mediaCount = 0;
};

struct DatabaseFootprint {
    std::int64_t fileBytes = 0;
    std::int64_t freeBytes = 0;
};

struct LastMessage {
    std::string text;
    std::string type;
    std::string attachment;
    std::string author;
};

class TranscriptReader {
public:
    TranscriptReader();
    virtual ~TranscriptReader();

    TranscriptReader(const TranscriptReader&) = delete;
    TranscriptReader& operator=(const TranscriptReader&) = delete;

    void close();
    bool isOpen() const { return db_ != nullptr; }
    bool open(const std::filesystem::path& file, const Bytes& key);

    Bytes media(const std::string& key) const;
    std::int64_t idForKey(const std::string& peer, const std::string& e2eId, bool outgoing) const;
    std::int64_t oldestOfType(const std::string& peer, const std::string& type, bool outgoing) const;
    StoredMessage messageByE2e(const std::string& e2eId, const std::string& peer) const;
    StoredMessage messageById(std::int64_t id) const;
    std::vector<StoredMessage> latestMessages(const std::string& peer, int limit) const;
    std::vector<StoredMessage> olderMessages(
        const std::string& peer, std::int64_t beforeId, int limit) const;
    std::vector<StoredMessage> newerMessages(
        const std::string& peer, std::int64_t afterId, int limit) const;
    std::vector<StoredMessage> messagesAround(
        const std::string& peer, std::int64_t id, int perSide) const;
    StoredMessage nextVoiceAfter(const std::string& peer, std::int64_t afterId) const;
    StoredMessage pictureBeside(const std::string& peer, std::int64_t id, bool later) const;
    bool hasMessagesBefore(const std::string& peer, std::int64_t id) const;
    bool hasMessagesAfter(const std::string& peer, std::int64_t id) const;
    // Newest first; only rows with text or a file name.
    std::vector<SearchableRow> searchableRows(const std::string& peer) const;
    // Seconds, 0 when the chat has none.
    std::int64_t chatTimer(const std::string& peer) const;
    // Empty when the bot shows no menu.
    std::string botMenu(const std::string& peer) const;
    // Oldest first.
    std::vector<std::pair<std::string, std::int64_t>> expiredBy(std::int64_t nowMs) const;
    LastMessage lastMessage(const std::string& peer) const;
    std::int64_t lastTime(const std::string& peer) const;
    // 0 when this side wrote nothing in the chat.
    std::int64_t newestOwnOrderKey(const std::string& peer) const;
    std::vector<std::string> conversationPeers() const;
    std::int64_t lastReadId(const std::string& peer) const;
    bool isPinned(const std::string& peer) const;
    int unreadCount(const std::string& peer) const;
    int unreadTotal() const;
    std::int64_t firstUnreadId(const std::string& peer) const;
    std::vector<Reaction> reactionsFor(const std::string& peer, const std::string& target) const;
    std::optional<GroupState> groupState(const std::string& peer) const;
    std::map<std::string, std::int64_t> groupReactionCounts(
        const std::string& peer, const std::string& target) const;
    std::vector<ChatWeight> chatWeights() const;
    DatabaseFootprint footprint() const;

protected:
    bool hasMediaTable() const;

    SqliteHandle db_;
    std::filesystem::path path_;
};

class TranscriptStore : public TranscriptReader {
public:
    bool open(const std::filesystem::path& file, const std::string& passphrase = {});
    const std::string& lastError() const { return lastError_; }

    [[nodiscard]] std::int64_t append(const StoredMessage& message);
    [[nodiscard]] bool updateStatus(std::int64_t id, int status);
    // Forward only, except to failure; nothing when the store failed, false when unchanged.
    [[nodiscard]] std::optional<bool> advanceStatus(std::int64_t id, int status);
    [[nodiscard]] std::optional<int> failUnsentOnLoad(
        int preparingStatus, int deliveringStatus, int failedStatus);
    [[nodiscard]] std::optional<int> settleUnfinishedNotes(const std::string& type,
        int preparingStatus, int settledStatus, const std::string& text);
    [[nodiscard]] bool markOutgoingReadUpTo(const std::string& peer, std::int64_t uptoId,
        int readStatus, int minStatus, int maxStatus);
    [[nodiscard]] bool setSavedPath(std::int64_t id, const std::string& path);
    [[nodiscard]] bool setHasPicture(std::int64_t id, bool has);
    [[nodiscard]] bool editContent(
        std::int64_t id, const std::string& text, const std::string& keyboard);
    [[nodiscard]] bool setType(std::int64_t id, const std::string& type);
    // Takes the row's picture, voice note and reactions with it.
    [[nodiscard]] bool removeById(std::int64_t id);
    // Takes every row of the chat and what hangs on them; the chat's settings stay.
    [[nodiscard]] bool clearPeer(const std::string& peer);
    [[nodiscard]] bool forgetPeer(const std::string& peer);
    [[nodiscard]] bool setLastReadId(const std::string& peer, std::int64_t id);
    [[nodiscard]] bool applyReadThrough(const std::string& peer, std::int64_t sentAtMs);
    [[nodiscard]] bool setPinned(const std::string& peer, bool pinned);
    [[nodiscard]] bool setChatTimer(const std::string& peer, std::int64_t seconds);
    [[nodiscard]] bool setBotMenu(const std::string& peer, const std::string& itemsJson);
    [[nodiscard]] bool setReaction(const std::string& peer, const std::string& target,
        const std::string& reactor, const std::string& emoji);
    [[nodiscard]] bool setGroupState(const std::string& peer, const GroupState& state);
    [[nodiscard]] bool dropGroupState(const std::string& peer);
    [[nodiscard]] bool setGroupReactionCounts(const std::string& peer, const std::string& target,
        const std::map<std::string, std::int64_t>& counts);
    std::int64_t pruneToLatest(const std::string& peer, int keep);
    std::int64_t pruneEveryChatToLatest(int keep);
    // Rewrites the file without the free pages deleted rows left behind.
    bool rebuild(std::string& reason);

private:
    bool failed();
    bool stampExpiry(std::int64_t id, const std::string& peer, std::int64_t atMs);
    bool stampNewlyRead(const std::string& peer, std::int64_t afterId, std::int64_t uptoId);
    bool clearPeerRows(const std::string& peer);
    bool removeMediaOfMessage(const std::string& e2eId);
    bool removeMediaOfPeer(const std::string& peer);
    bool removeMediaOfTrimmed(const std::string& peer, int keep);
    std::int64_t pruneRowsOf(const std::string& peer, int keep);

    std::string lastError_;
};

}  // namespace bazarish::client
