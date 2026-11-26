// Bazarish project (c) 2026
#include "AccountDb.hpp"
#include "Mentions.hpp"
#include "MessageTypes.hpp"
#include "TranscriptIngest.hpp"

#include "TestUtil.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace fs = std::filesystem;

namespace {

constexpr const char* kOwn = "own";
constexpr const char* kPeer = "peer";
constexpr const char* kPeerDevice = "peerdev234";
constexpr const char* kOtherOwnDevice = "tabdev2345";
constexpr std::int64_t kDeliveryLagMs = 3000;

class Notes final : public IngestNotes {
public:
    std::string chatCleared(bool, const std::string&) const override { return "cleared"; }
    std::string chatTimer(std::int64_t, bool, const std::string&) const override { return "timer"; }
    std::string contactAccepted(const std::string&) const override { return "accepted"; }
    std::string unsupported(const std::string&, const Bytes&) const override { return "unsupported"; }
    std::string unreadable() const override { return "unreadable"; }
    std::string callRecord(const bool incoming, const std::string& outcome) const override
    {
        return std::string(incoming ? "incoming call " : "outgoing call ") + outcome;
    }
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

constexpr const char* kHost = "host";
constexpr std::int64_t kBlockAt = 1000;
constexpr std::size_t kTwoCandidates = 2;

class GroupHeard final : public IngestListener {
public:
    void memberListWanted(const std::string& peer) override { asked.push_back(peer); }
    void groupReactionAdded(const std::string&, const std::string& target,
        const std::string& emoji) override
    {
        counted.push_back(target + " " + emoji);
    }
    std::vector<std::string> asked;
    std::vector<std::string> counted;
};

IncomingMessage fromHost(const std::string& type, const std::string& e2eId)
{
    IncomingMessage message;
    message.contentType = type;
    message.fromFingerprint = kHost;
    message.e2eId = e2eId;
    message.sentAt = millisNow();
    message.group = GroupBlock{GroupKind::eGroup, 0, true, false, kBlockAt};
    return message;
}

IncomingMessage listLetter(const std::string& e2eId, const MemberListLetter& letter)
{
    IncomingMessage message = fromHost(kTypeGroupMembers, e2eId);
    message.memberList = letter;
    return message;
}

MemberListLetter fullPart(std::int64_t part, std::int64_t parts, std::int64_t total,
    std::vector<std::string> names, std::string you = {})
{
    MemberListLetter letter;
    letter.op = MemberListOp::eFull;
    letter.part = part;
    letter.parts = parts;
    letter.total = total;
    letter.names = std::move(names);
    letter.you = std::move(you);
    return letter;
}

MemberListLetter change(MemberListOp op, std::vector<std::string> names, std::int64_t total,
    std::string you = {})
{
    MemberListLetter letter;
    letter.op = op;
    letter.names = std::move(names);
    letter.total = total;
    letter.you = std::move(you);
    return letter;
}

std::string asciiLower(const std::string& text)
{
    std::string lower = text;
    for (char& c : lower) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return lower;
}

std::vector<std::string> mentioned(const std::string& text, const std::vector<std::string>& names)
{
    std::vector<std::string> found;
    for (const MentionSpan& span : findMentions(text, names)) {
        found.push_back(span.name);
    }
    return found;
}

void checkMentionRules()
{
    const std::vector<std::string> names{"Anna", "Anna Maria", "Bob.", "Иван"};
    using Names = std::vector<std::string>;
    CHECK(mentionForm("Anna Maria") == "Anna_Maria");
    CHECK(mentioned("@Anna hi", names) == Names{"Anna"});
    CHECK(mentioned("hi @Anna_Maria, and @Anna!", names) == (Names{"Anna Maria", "Anna"}));
    CHECK(mentioned("@Anna Maria", names) == Names{"Anna"});
    CHECK(mentioned("mail anna@Anna", names).empty());
    CHECK(mentioned("@Annabelle", names).empty());
    CHECK(mentioned("@Anna_", names).empty());
    CHECK(mentioned("(@Anna)", names) == Names{"Anna"});
    CHECK(mentioned("\xC2\xAB@\xD0\x98\xD0\xB2\xD0\xB0\xD0\xBD\xC2\xBB", names) == Names{"Иван"});
    CHECK(mentioned("@Иван\xE2\x80\xA6", names) == Names{"Иван"});
    CHECK(mentioned("@Иванович", names).empty());
    CHECK(mentioned("@Bob.", names) == Names{"Bob."});
    CHECK(mentioned("@Bob.?!", names) == Names{"Bob."});
    CHECK(mentioned("@Bob", names).empty());
    CHECK(mentioned("@@Anna", names).empty());
    CHECK(mentioned("x\xC2\xA0@Anna", names) == Names{"Anna"});
    const std::vector<MentionSpan> spans = findMentions("hey @Anna_Maria.", names);
    CHECK(spans.size() == 1 && spans[0].offset == 4 && spans[0].length == 11);
    CHECK(mentionsName("ping @Me", {}, "Me"));
    CHECK(!mentionsName("ping @Me", {"Me"}, ""));

    const std::vector<std::string> members{"anna", "Anna Maria", "Annet", "Bob", "Me", "Anya",
        "Ann", "Annie"};
    const std::vector<std::string> picked = mentionCandidates(members, "Me", "an", asciiLower);
    CHECK(picked.size() == kMaxMentionCandidates);
    CHECK(picked.front() == "Ann");
    CHECK(mentionCandidates(members, "Me", "Anna M", asciiLower) == Names{"Anna Maria"});
    CHECK(mentionCandidates(members, "Me", "anna", asciiLower).size() == kTwoCandidates);
    CHECK(mentionCandidates(members, "Me", "m", asciiLower).empty());
}

bool refused(const nlohmann::json& body)
{
    try {
        (void)memberListFromJson(body);
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

void checkLetterBounds()
{
    MemberListLetter full = fullPart(1, 1, 1, {"Ann"}, "Ann");
    const MemberListLetter back = memberListFromJson(memberListToJson(full));
    CHECK(back.op == MemberListOp::eFull && back.names == full.names && back.you == "Ann");
    nlohmann::json body = memberListToJson(full);
    body["you"] = "Bob";
    CHECK(refused(body));
    body = memberListToJson(full);
    body["part"] = 2;
    CHECK(refused(body));
    body = memberListToJson(full);
    body["names"] = nlohmann::json::array({std::string(kMaxGroupNameBytes + 1, 'n')});
    body.erase("you");
    CHECK(refused(body));
    body["names"] = std::vector<std::string>(kMaxMemberNamesPerLetter + 1, "n");
    CHECK(refused(body));
    body = memberListToJson(full);
    body["contactableNames"] = nlohmann::json::array({"Bob"});
    CHECK(refused(body));
    body.erase("contactableNames");
    CHECK(refused(body));
    CHECK(refused({{"op", "renamed"}}));
    CHECK(memberListFromJson({{"op", "none"}}).op == MemberListOp::eNone);
}

void checkGroupIngest(const fs::path& file)
{
    TranscriptStore store;
    CHECK(store.open(file, "secret"));
    const Notes notes;
    GroupHeard listener;
    TranscriptIngest ingest(store, []() { return std::string(kOwn); }, notes, listener);

    CHECK(store.memberListState(kHost) == MemberListState::eUnknown);
    CHECK(ingest.takeIn(fromHost(kTypeGroupState, "state-1")));
    CHECK(ingest.takeIn(fromHost(kTypeGroupState, "state-2")));
    CHECK(listener.asked.size() == 1);

    CHECK(ingest.takeIn(listLetter("full-1", fullPart(1, 2, 3, {"Anna", "Me Self"}, "Me Self"))));
    CHECK(store.memberListState(kHost) == MemberListState::eUnknown);
    MemberListLetter lastPart = fullPart(2, 2, 3, {"Bob"});
    lastPart.contactable = {"Bob"};
    CHECK(ingest.takeIn(listLetter("full-2", lastPart)));
    CHECK(store.memberListState(kHost) == MemberListState::eHeld);
    CHECK(store.groupMembers(kHost) == (std::vector<std::string>{"Anna", "Bob", "Me Self"}));
    CHECK(store.ownGroupName(kHost) == "Me Self");
    CHECK(listener.asked.size() == 1);

    CHECK(store.groupContactable(kHost) == (std::vector<std::string>{"Bob"}));

    MemberListLetter cleo = change(MemberListOp::eAdded, {"Cleo"}, 4);
    cleo.contactable = {"Cleo"};
    CHECK(ingest.takeIn(listLetter("add-1", cleo)));
    CHECK(store.groupMembers(kHost).size() == 4);
    CHECK(ingest.takeIn(listLetter("closed-1", change(MemberListOp::eChanged, {"Bob"}, 4))));
    CHECK(store.groupContactable(kHost) == (std::vector<std::string>{"Cleo"}));
    CHECK(ingest.takeIn(listLetter("left-1", change(MemberListOp::eRemoved, {"Cleo"}, 3))));
    CHECK(store.groupContactable(kHost).empty());
    CHECK(ingest.takeIn(listLetter("back-1", change(MemberListOp::eAdded, {"Cleo"}, 4))));
    CHECK(ingest.takeIn(listLetter("ren-1", change(MemberListOp::eRemoved, {"Me Self"}, 3))));
    CHECK(store.ownGroupName(kHost).empty());
    CHECK(ingest.takeIn(listLetter("ren-2", change(MemberListOp::eAdded, {"Me"}, 4, "Me"))));
    CHECK(store.ownGroupName(kHost) == "Me");
    CHECK(store.memberListState(kHost) == MemberListState::eHeld);
    CHECK(listener.asked.size() == 1);

    IncomingMessage outgoing = fromHost(kTypeText, "mine");
    outgoing.group.reset();
    outgoing.sentByUs = true;
    outgoing.text = "my post";
    CHECK(ingest.takeIn(outgoing));

    IncomingMessage plain = fromHost(kTypeText, "plain");
    plain.text = "hello @Anna";
    plain.author = "Bob";
    CHECK(ingest.takeIn(plain));
    IncomingMessage named = fromHost(kTypeText, "named");
    named.text = "@Me, look";
    named.author = "Anna";
    CHECK(ingest.takeIn(named));
    IncomingMessage reply = fromHost(kTypeText, "reply");
    reply.text = "agreed";
    reply.replyTo = "mine";
    reply.author = "Cleo";
    CHECK(ingest.takeIn(reply));
    const std::int64_t plainId = store.idForKey(kHost, "plain", false);
    const std::int64_t namedId = store.idForKey(kHost, "named", false);
    const std::int64_t replyId = store.idForKey(kHost, "reply", false);
    CHECK(!store.messageById(plainId).mentionsMe);
    CHECK(store.messageById(namedId).mentionsMe);
    CHECK(store.messageById(replyId).mentionsMe);
    CHECK(store.unreadMentionCount(kHost) == 2);
    CHECK(store.firstUnreadMentionId(kHost) == namedId);

    IncomingMessage edit = fromHost(kTypeEdit, "edit-1");
    edit.refId = "plain";
    edit.text = "hello @Me";
    CHECK(ingest.takeIn(edit));
    CHECK(store.messageById(plainId).mentionsMe);
    CHECK(store.unreadMentionCount(kHost) == 3);
    CHECK(store.firstUnreadMentionId(kHost) == plainId);
    CHECK(store.setLastReadId(kHost, namedId));
    CHECK(store.unreadMentionCount(kHost) == 1);
    CHECK(store.firstUnreadMentionId(kHost) == replyId);

    IncomingMessage counting = fromHost(kTypeGroupReactions, "counts-1");
    counting.groupReactionsJson = R"([{"ref":"mine","counts":{"👍":1}}])";
    CHECK(ingest.takeIn(counting));
    CHECK(listener.counted == (std::vector<std::string>{"mine 👍"}));
    counting.e2eId = "counts-2";
    CHECK(ingest.takeIn(counting));
    CHECK(listener.counted.size() == 1);
    counting.e2eId = "counts-3";
    counting.groupReactionsJson = R"([{"ref":"mine","counts":{"👍":1,"😀":2}}])";
    CHECK(ingest.takeIn(counting));
    CHECK(listener.counted == (std::vector<std::string>{"mine 👍", "mine 😀"}));
    counting.e2eId = "counts-4";
    counting.groupReactionsJson = R"([{"ref":"mine","counts":{"😀":1}}])";
    CHECK(ingest.takeIn(counting));
    CHECK(listener.counted.size() == 2);

    CHECK(ingest.takeIn(listLetter("drop-1", change(MemberListOp::eRemoved, {"Bob"}, 2))));
    CHECK(store.memberListState(kHost) == MemberListState::eUnknown);
    CHECK(listener.asked.size() == 2);
    CHECK(ingest.takeIn(listLetter("full-3", fullPart(2, 2, 3, {"Bob"}))));
    CHECK(listener.asked.size() == 3);
    CHECK(ingest.takeIn(listLetter("full-4", fullPart(1, 1, 2, {"Anna", "Me"}, "Me"))));
    CHECK(store.memberListState(kHost) == MemberListState::eHeld);
    CHECK(ingest.takeIn(listLetter("full-5", fullPart(1, 1, 3, {"Anna", "Me"}, "Me"))));
    CHECK(listener.asked.size() == 4);

    MemberListLetter none;
    none.op = MemberListOp::eNone;
    CHECK(ingest.takeIn(listLetter("none-1", none)));
    CHECK(store.memberListState(kHost) == MemberListState::eNone);
    CHECK(store.groupMembers(kHost).empty());
    CHECK(ingest.takeIn(fromHost(kTypeGroupState, "state-3")));
    CHECK(listener.asked.size() == 4);
    store.close();
}

}  // namespace

int main()
try {
    const testutil::ScratchDir scratch("ingest");
    const fs::path& root = scratch.path();
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

        CHECK(ingest.takeIn(incoming(kTypeUnreadable, "sealed-elsewhere", 0)));
        bool noted = false;
        for (const StoredMessage& row : store.latestMessages(kPeer, 10)) {
            if (row.e2eId == "sealed-elsewhere") {
                noted = row.type == kTypeSystem && row.text == "unreadable" && !row.outgoing;
            }
        }
        CHECK(noted);

        IncomingMessage theirs = incoming(kTypeText, "theirs", composedAt + 2);
        theirs.fromDevice = kPeerDevice;
        CHECK(ingest.takeIn(theirs));
        IncomingMessage echo = incoming(kTypeText, "echo", composedAt + 3);
        echo.sentByUs = true;
        echo.fromDevice = kOtherOwnDevice;
        CHECK(ingest.takeIn(echo));
        CHECK(store.messageById(store.idForKey(kPeer, "theirs", false)).device == kPeerDevice);
        const StoredMessage echoed = store.messageById(store.idForKey(kPeer, "echo", true));
        CHECK(echoed.outgoing);
        CHECK(echoed.device == kOtherOwnDevice);

        IncomingMessage record = incoming(kTypeCallRecord, "call-record", composedAt + 4);
        record.sentByUs = true;
        record.callIncoming = true;
        record.text = kCallMarkMissed;
        CHECK(ingest.takeIn(record));
        IncomingMessage otherDevicesRecord = record;
        otherDevicesRecord.text = kCallMarkAnswered;
        CHECK(ingest.takeIn(otherDevicesRecord));
        const StoredMessage recorded
            = store.messageById(store.idForKey(kPeer, "call-record", true));
        CHECK(recorded.type == kTypeSystem);
        CHECK(recorded.text == std::string("incoming call ") + kCallMarkMissed);
        CHECK(recorded.ts == composedAt + 4);
        int recordRows = 0;
        for (const StoredMessage& row : store.latestMessages(kPeer, 20)) {
            recordRows += row.e2eId == "call-record" ? 1 : 0;
        }
        CHECK(recordRows == 1);
        IncomingMessage forged = incoming(kTypeCallRecord, "forged-record", composedAt + 5);
        forged.text = kCallMarkAnswered;
        CHECK(ingest.takeIn(forged));
        CHECK(store.idForKey(kPeer, "forged-record", false) == 0);
        store.close();
    }
    checkMentionRules();
    checkLetterBounds();
    checkGroupIngest(file);
    std::fprintf(stderr, "TestTranscriptIngest passed\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
