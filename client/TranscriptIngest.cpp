// Bazarish project (c) 2026
#include "TranscriptIngest.hpp"

#include "AudioCodec.hpp"
#include "MediaKeys.hpp"
#include "MessageTypes.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/JsonRead.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <utility>

namespace bazarish::client {

namespace {

constexpr int kReceived = static_cast<int>(DeliveryState::eReceived);
constexpr int kAtRecipientServer = static_cast<int>(DeliveryState::eAtRecipientServer);
constexpr int kDelivered = static_cast<int>(DeliveryState::eDelivered);
constexpr std::size_t kMaxReceiptsAheadPerPeer = 1024;
constexpr std::size_t kMaxPeersWithReceiptsAhead = 4096;

struct Placement {
    std::int64_t displayTs = 0;
    std::int64_t orderKey = 0;
};

// A row from the other side never goes above what this side had written before it came.
Placement placeReceived(const std::int64_t sentAtMs, const std::int64_t arrivalMs,
    const std::int64_t floor)
{
    const std::int64_t written = sentAtMs > 0 ? sentAtMs : arrivalMs;
    return {written, std::max(written, floor)};
}

}  // namespace

TranscriptIngest::TranscriptIngest(TranscriptStore& store, OwnFingerprintFn ownFingerprint,
    const IngestNotes& notes, IngestListener& listener)
    : store_(store)
    , own_(std::move(ownFingerprint))
    , notes_(notes)
    , listener_(listener)
{
}

std::int64_t TranscriptIngest::orderFloor(const IncomingMessage& message) const
{
    if (message.sentByUs) {
        return 0;
    }
    const std::int64_t own = store_.newestOwnOrderKey(message.fromFingerprint);
    return own > 0 ? own + 1 : 0;
}

std::int64_t TranscriptIngest::localIdOf(const IncomingMessage& message) const
{
    return store_.idForKey(message.fromFingerprint, message.refId, message.sentByUs);
}

std::int64_t TranscriptIngest::appendNote(
    const IncomingMessage& message, const std::string& text, const bool placed)
{
    StoredMessage note;
    note.peer = message.fromFingerprint;
    note.e2eId = message.e2eId;
    note.type = kTypeSystem;
    note.text = text;
    if (placed) {
        const Placement placement = placeReceived(message.sentAt, nowMillis(), orderFloor(message));
        note.ts = placement.displayTs;
        note.orderKey = placement.orderKey;
    } else {
        note.ts = nowMillis();
        note.orderKey = note.ts;
    }
    note.status = kReceived;
    return store_.append(note);
}

bool TranscriptIngest::takeIn(const IncomingMessage& message)
{
    const std::string& peer = message.fromFingerprint;
    const std::string& type = message.contentType;
    const std::string& incomingId = message.e2eId;

    if (!incomingId.empty() && store_.idForKey(peer, incomingId, message.sentByUs) != 0) {
        return true;
    }
    if (type.starts_with(kTypeCallPrefix)) {
        return true;
    }
    if (!message.sentByUs && !noteGroupBlock(message)) {
        return false;
    }
    if (type == kTypeGroupState || type == kTypePresenceSchedule) {
        return true;
    }
    if (type == kTypeGroupReactions) {
        return applyGroupReactions(peer, message.groupReactionsJson);
    }
    if (type == kTypeContactRequest && !message.sentByUs
        && store_.oldestOfType(peer, type, false) != 0) {
        log::info("a second contact request from {} keeps the plate it already has",
            log::redact(peer));
        return true;
    }

    if (type == kTypeDeviceChatClear) {
        if (!message.refId.empty()) {
            if (!store_.clearPeer(message.refId)) {
                return false;
            }
            receiptsAhead_.erase(message.refId);
            listener_.peerReset(message.refId);
        }
        return true;
    }
    if (type == kTypeDeviceAccountName) {
        if (!message.text.empty()) {
            listener_.accountRenamed(message.text);
        }
        return true;
    }
    if (type == kTypeDeviceAccountPrefs) {
        listener_.settingsAsked();
        return true;
    }
    if (type == kTypeDeviceSavedClear) {
        const std::string own = own_();
        if (!store_.clearPeer(own)) {
            return false;
        }
        receiptsAhead_.erase(own);
        listener_.peerReset(own);
        return true;
    }
    if (type == kTypeDeviceContactRemove) {
        if (!message.refId.empty()) {
            if (!store_.forgetPeer(message.refId)) {
                return false;
            }
            receiptsAhead_.erase(message.refId);
            listener_.peerForgotten(message.refId);
        }
        return true;
    }
    if (type == kTypeDeviceContactBlock || type == kTypeDeviceContactPrefs
        || type == kTypeDeviceContactAccepted || type == kTypeDeviceContact) {
        listener_.contactsRevised();
        return true;
    }
    if (type == kTypeDeviceRead) {
        std::int64_t through = 0;
        if (std::from_chars(message.text.data(), message.text.data() + message.text.size(), through)
                .ec
            != std::errc()) {
            through = 0;
        }
        if (!message.refId.empty() && through > 0) {
            if (!store_.applyReadThrough(message.refId, through)) {
                return false;
            }
            listener_.readElsewhere(message.refId, through);
        }
        return true;
    }
    if (type == kTypeDeviceChatPin) {
        if (!message.refId.empty()) {
            if (!store_.setPinned(message.refId, message.text == "1")) {
                return false;
            }
            listener_.chatsChanged();
        }
        return true;
    }

    if (type == kTypeReceipt) {
        const std::int64_t localId = store_.idForKey(peer, message.refId, true);
        if (localId == 0) {
            log::info("receipt for {} arrived before the message it is about", message.refId);
            noteReceiptAhead(peer, message.refId);
            return true;
        }
        log::info("receipt for {} applied to row {}", message.refId, localId);
        return markOutgoingRead(peer, localId);
    }
    if (type == kTypeReaction) {
        const std::string reactor = message.sentByUs ? own_() : peer;
        if (!store_.setReaction(peer, message.refId, reactor, message.text)) {
            return false;
        }
        listener_.reactionSet(peer, message.refId, reactor, message.text);
        return true;
    }
    if (type == kTypeEdit) {
        const std::int64_t localId = localIdOf(message);
        if (localId != 0) {
            if (!store_.editContent(localId, message.text, message.keyboardJson)) {
                return false;
            }
            listener_.rowChanged(peer, localId);
            listener_.editArrived(peer, localId, message.refId);
        }
        return true;
    }
    if (type == kTypeDelete) {
        const std::int64_t localId = localIdOf(message);
        if (localId != 0) {
            if (!store_.removeById(localId)) {
                return false;
            }
            listener_.rowRemoved(peer, localId, message.refId);
        }
        return true;
    }
    if (type == kTypeChatClear) {
        if (!store_.clearPeer(peer)
            || appendNote(message, notes_.chatCleared(message.sentByUs, peer), false) == 0) {
            return false;
        }
        receiptsAhead_.erase(peer);
        listener_.peerReset(peer);
        return true;
    }
    if (type == kTypeBotMenu) {
        if (!store_.setBotMenu(peer, message.menuItemsJson)) {
            return false;
        }
        listener_.botMenuChanged(peer);
        return true;
    }
    if (type == kTypeChatTimer) {
        if (store_.groupState(peer).has_value()) {
            log::info("an auto-delete timer from a group host ignored");
            return true;
        }
        if (!store_.setChatTimer(peer, message.timerSeconds)) {
            return false;
        }
        const std::int64_t id = appendNote(
            message, notes_.chatTimer(message.timerSeconds, message.sentByUs, peer), true);
        if (id == 0) {
            return false;
        }
        listener_.chatTimerChanged(peer, message.timerSeconds);
        listener_.rowAdded(peer, id, message.sentByUs);
        return true;
    }
    if (type == kTypeContactAccept) {
        const std::int64_t id = appendNote(message, notes_.contactAccepted(peer), true);
        if (id == 0) {
            return false;
        }
        listener_.rowAdded(peer, id, false);
        const std::int64_t request = store_.oldestOfType(peer, kTypeContactRequest, true);
        return request == 0 || markOutgoingRead(peer, request);
    }
    if (type == kTypeUnsupported) {
        StoredMessage kept;
        kept.peer = peer;
        kept.outgoing = message.sentByUs;
        kept.e2eId = incomingId;
        kept.type = type;
        kept.device = message.fromDevice;
        kept.text = notes_.unsupported(message.rawType, message.rawBody);
        const Placement placement = placeReceived(message.sentAt, nowMillis(), orderFloor(message));
        kept.ts = placement.displayTs;
        kept.orderKey = placement.orderKey;
        kept.status = kept.outgoing ? kAtRecipientServer : kReceived;
        kept.id = store_.append(kept);
        if (kept.id == 0) {
            return false;
        }
        listener_.rowAdded(peer, kept.id, kept.outgoing);
        return true;
    }

    if (type != kTypeContactRequest && message.text.empty() && message.callbackData.empty()
        && message.attachmentName.empty() && message.attachmentRef.empty()
        && message.attachmentSize == 0 && message.keyboardJson.empty()) {
        log::info("silent control message ({}) not shown", type);
        return true;
    }

    StoredMessage m;
    m.peer = peer;
    m.outgoing = message.sentByUs;
    m.type = type;
    m.e2eId = incomingId;
    m.text = type == kTypeBotCallback ? message.callbackData : message.text;
    m.replyTo = type == kTypeBotCallback ? message.refId : message.replyTo;
    m.forwarded = message.forwarded;
    m.device = message.fromDevice;
    m.attName = message.attachmentName;
    m.attMime = message.attachmentMime;
    m.attSize = static_cast<std::int64_t>(message.attachmentSize);
    m.attDurationMs = message.attachmentDurationMs;
    m.attRef = message.attachmentRef;
    m.keyboard = message.keyboardJson;
    if (type == kTypeAudio && !incomingId.empty()) {
        const Bytes voice = store_.media(kVoiceKeyPrefix + incomingId);
        if (!voice.empty()) {
            try {
                m.attWave = voiceWaveformHex(voice);
            } catch (const std::exception& error) {
                log::warn("voice waveform: {}", error.what());
            }
        }
    }
    if (message.group) {
        m.author = message.author;
        m.contactable = message.contactable;
        m.fromHost = message.fromHost;
    }
    const Placement placement = placeReceived(message.sentAt, nowMillis(), orderFloor(message));
    m.ts = placement.displayTs;
    m.orderKey = placement.orderKey;
    m.status = m.outgoing ? (peer == own_() ? kDelivered : kAtRecipientServer) : kReceived;
    m.id = store_.append(m);
    if (m.id == 0) {
        return false;
    }
    if (m.outgoing && !m.e2eId.empty()) {
        const auto waiting = receiptsAhead_.find(peer);
        if (waiting != receiptsAhead_.end() && waiting->second.erase(m.e2eId) > 0
            && !markOutgoingRead(peer, m.id)) {
            return false;
        }
    }
    if (m.type == kTypeImage && !m.e2eId.empty()) {
        if (!store_.setHasPicture(m.id, !store_.media(kPictureKeyPrefix + m.e2eId).empty())) {
            return false;
        }
    }
    listener_.rowAdded(peer, m.id, false);
    if (!m.outgoing) {
        listener_.messageArrived(peer);
    }
    return true;
}

bool TranscriptIngest::noteGroupBlock(const IncomingMessage& message)
{
    const std::string& peer = message.fromFingerprint;
    const std::optional<GroupState> held = store_.groupState(peer);
    if (!message.group) {
        if (held && message.sentAt > held->at) {
            if (!store_.dropGroupState(peer)) {
                return false;
            }
            listener_.groupChanged(peer);
        }
        return true;
    }
    GroupState state;
    state.kind = message.group->kind == GroupKind::eChannel ? kGroupKindChannel : kGroupKindGroup;
    state.members = message.group->members;
    state.write = message.group->write;
    state.admin = message.group->admin;
    state.at = message.group->at;
    if (held && held->at > state.at) {
        return true;
    }
    if (!store_.setGroupState(peer, state)) {
        return false;
    }
    listener_.groupChanged(peer);
    return true;
}

bool TranscriptIngest::applyGroupReactions(const std::string& peer, const std::string& json)
{
    const nlohmann::json entries = parseJsonOrDiscarded(json);
    if (entries.is_array()) {
        for (const nlohmann::json& entry : entries) {
            if (!entry.is_object()) {
                continue;
            }
            std::map<std::string, std::int64_t> counts;
            const nlohmann::json given = entry.value("counts", nlohmann::json::object());
            for (auto it = given.begin(); given.is_object() && it != given.end(); ++it) {
                if (it.value().is_number_integer()) {
                    counts[it.key()] = it.value().get<std::int64_t>();
                }
            }
            if (!store_.setGroupReactionCounts(peer, entry.value("ref", std::string()), counts)) {
                return false;
            }
        }
    }
    listener_.groupReactionsChanged(peer);
    return true;
}

void TranscriptIngest::noteReceiptAhead(const std::string& peer, const std::string& refId)
{
    const auto held = receiptsAhead_.find(peer);
    const bool room = held == receiptsAhead_.end()
        ? receiptsAhead_.size() < kMaxPeersWithReceiptsAhead
        : held->second.size() < kMaxReceiptsAheadPerPeer;
    if (!room) {
        log::info(
            "a receipt ahead of its message from {} is dropped: too many wait", log::redact(peer));
        return;
    }
    receiptsAhead_[peer].insert(refId);
}

bool TranscriptIngest::markOutgoingRead(const std::string& peer, const std::int64_t uptoId)
{
    if (!store_.markOutgoingReadUpTo(peer, uptoId, kDelivered, kAtRecipientServer, kAtRecipientServer)) {
        return false;
    }
    listener_.deliveredThrough(peer, uptoId);
    return true;
}

}  // namespace bazarish::client
