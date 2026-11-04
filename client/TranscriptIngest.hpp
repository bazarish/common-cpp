// Bazarish project (c) 2026
#pragma once

#include "Session.hpp"
#include "TranscriptDb.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>

namespace bazarish::client {

// The words of the rows this side writes about what happened; each front-end says them its own way.
class IngestNotes {
public:
    virtual ~IngestNotes() = default;
    virtual std::string chatCleared(bool ours, const std::string& peer) const = 0;
    virtual std::string chatTimer(std::int64_t seconds, bool ours, const std::string& peer) const = 0;
    virtual std::string contactAccepted(const std::string& peer) const = 0;
    virtual std::string unsupported(const std::string& rawType, const Bytes& rawBody) const = 0;
};

class IngestListener {
public:
    virtual ~IngestListener() = default;
    virtual void rowAdded(const std::string&, std::int64_t, bool) {}
    virtual void rowChanged(const std::string&, std::int64_t) {}
    virtual void rowRemoved(const std::string&, std::int64_t, const std::string&) {}
    virtual void peerReset(const std::string&) {}
    virtual void peerForgotten(const std::string&) {}
    virtual void chatTimerChanged(const std::string&, std::int64_t) {}
    virtual void botMenuChanged(const std::string&) {}
    virtual void chatsChanged() {}
    virtual void deliveredThrough(const std::string&, std::int64_t) {}
    virtual void reactionSet(
        const std::string&, const std::string&, const std::string&, const std::string&) {}
    virtual void groupReactionsChanged(const std::string&) {}
    virtual void groupChanged(const std::string&) {}
    virtual void accountRenamed(const std::string&) {}
    virtual void contactsRevised() {}
    virtual void settingsAsked() {}
    // throughMs is the send time of the newest message another device read.
    virtual void readElsewhere(const std::string&, std::int64_t) {}
    virtual void editArrived(const std::string&, std::int64_t, const std::string&) {}
    virtual void messageArrived(const std::string&) {}
};

// Applies what the mailbox brought to the account's conversations.
class TranscriptIngest {
public:
    using OwnFingerprintFn = std::function<std::string()>;

    TranscriptIngest(TranscriptStore& store, OwnFingerprintFn ownFingerprint,
        const IngestNotes& notes, IngestListener& listener);

    // False when the store refused a write; the message is then not to be acknowledged.
    [[nodiscard]] bool takeIn(const IncomingMessage& message);

private:
    bool noteGroupBlock(const IncomingMessage& message);
    bool applyGroupReactions(const std::string& peer, const std::string& json);
    bool markOutgoingRead(const std::string& peer, std::int64_t uptoId);
    std::int64_t appendNote(const IncomingMessage& message, const std::string& text, bool placed);
    std::int64_t orderFloor(const IncomingMessage& message) const;
    std::int64_t localIdOf(const IncomingMessage& message) const;

    TranscriptStore& store_;
    const OwnFingerprintFn own_;
    const IngestNotes& notes_;
    IngestListener& listener_;
    std::map<std::string, std::set<std::string>> receiptsAhead_;
};

}  // namespace bazarish::client
