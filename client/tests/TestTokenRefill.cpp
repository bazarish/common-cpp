// Bazarish project (c) 2026
#include "Client.hpp"
#include "OutboundCourier.hpp"
#include "Session.hpp"
#include "WireLog.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/Tokens.hpp>

#include <bazarish/FederationFrame.hpp>
#include <bazarish/HttpServer.hpp>

#include <functional>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::client;

namespace {

namespace fs = std::filesystem;

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

auth::Headers collectAuthHeaders(const http::Request& request)
{
    auth::Headers headers;
    for (const char* const name : {auth::kHeaderKeys, auth::kHeaderTimestamp,
             auth::kHeaderSignatureClassical, auth::kHeaderSignaturePq}) {
        if (request.hasHeader(name)) {
            headers[name] = request.header(name);
        }
    }
    return headers;
}

// Verifies the request signature against the real path and returns the caller
// fingerprint, mirroring the server-side authenticated() wrapper.
std::string requireCaller(const http::Request& request)
{
    return auth::verifyRequest(collectAuthHeaders(request), nowSeconds(), request.method,
        request.path, Bytes(request.body.begin(), request.body.end()));
}

// The tests write handlers the way the stub server used to take them - fill in
// a response - while the server hands one back; this bridges the two shapes.
using StubHandler = std::function<void(const http::Request&, http::Response&)>;

http::Handler stub(StubHandler handler)
{
    return [handler = std::move(handler)](const http::Request& request) {
        http::Response response;
        handler(request, response);
        return response;
    };
}

http::Server::Options localOptions()
{
    http::Server::Options options;
    options.port = 0;  // the kernel picks one
    return options;
}

void respondJson(http::Response& response, const nlohmann::json& body)
{
    response.contentType = "application/json";
    response.body = body.dump();
}

// A minimal but faithful stateful messaging server for two co-located users: it
// stores per-mailbox blobs, tracks each mailbox's registered token hashes and
// consumes exactly one on every content delivery (rejecting an unregistered
// token), and hands back each user's self-signed subscription certificate. Every
// handler runs on the server's own thread while the test drives the sessions on
// the main thread, so all state is guarded by one mutex.
struct Mock {
    std::mutex mu;
    std::string serverFp;
    Key serverSealing = Key::generateSealing();  // one serving key shared by both dests
    std::map<std::string, std::string> destFor;  // fingerprint -> serving destination
    std::map<std::string, std::string> certFor;  // fingerprint -> contact card (base64 DER)
    std::map<std::string, std::string> viewFor;  // fingerprint -> card-read capability
    struct Item {
        std::string id;
        std::string cls;
        Bytes payload;
    };
    std::map<std::string, std::vector<Item>> mailbox;         // recipient fp -> stored items
    std::map<std::string, std::set<std::string>> registered;  // owner fp -> valid token hashes (b64)
    std::map<std::string, std::set<std::string>> singletons;  // owner fp -> hashes registered 1-at-a-time
    std::map<std::string, std::set<std::string>> seenIds;     // recipient fp -> admitted deliveryIds
    int nextId = 1;
    // A delivery into this mailbox that spends one of the mailbox owner's OWN
    // singleton-registered tokens sets the flag: that is exactly the prepaid-token
    // refill path (a batch token would not be a singleton).
    std::string watchMailbox;
    bool refillUsedPrepaid = false;
};

// A send leaves on the courier's own thread, so a test that wants to see the far
// side of one waits for it rather than assuming it has landed.
bool waitFor(const std::function<bool()>& done)
{
    constexpr int kWaitMs = 5000;
    constexpr int kPollMs = 10;
    for (int waited = 0; waited < kWaitMs; waited += kPollMs) {
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
    }
    return done();
}

// The recipient's server at the other end of a delivery, in process. It reads
// the frame the courier really writes, unseals the envelope, does the token
// bookkeeping a delivery engine does, and signs the confirmation the same way -
// so what is exercised here is the delivery, not a stub of one.
class MockServerStream final : public DeliveryStream {
public:
    MockServerStream(Mock& mock, const Key& signingKey)
        : mock_(mock)
        , signingKey_(signingKey)
    {
    }

    void writeAll(const void* const data, const std::size_t size) override
    {
        const auto* const in = static_cast<const char*>(data);
        written_.append(in, size);
    }

    void readExact(void* const buffer, const std::size_t size) override
    {
        if (reply_.empty()) {
            reply_ = serve();
        }
        CHECK(sent_ + size <= reply_.size());
        std::memcpy(buffer, reply_.data() + sent_, size);
        sent_ += size;
    }

    void close() override {}

private:
    std::string serve()
    {
        const std::size_t lineEnd = written_.find('\n');
        CHECK(lineEnd != std::string::npos);
        const nlohmann::json header = nlohmann::json::parse(written_.substr(0, lineEnd));
        CHECK(header.at("op") == "deliver");
        const std::size_t length = header.at("len").get<std::size_t>();
        const std::string payloadText = written_.substr(lineEnd + 1, length);
        CHECK(payloadText.size() == length);
        const Bytes payload(payloadText.begin(), payloadText.end());
        const Bytes sealed = fromBase64(header.at("sealed").get<std::string>());
        const nlohmann::json inner = nlohmann::json::parse(cms::unseal(sealed, mock_.serverSealing));
        const std::string cls = inner.at("class").get<std::string>();
        const std::string mailbox = inner.at("mailbox").get<std::string>();
        const std::string deliveryId = inner.at("deliveryId").get<std::string>();

        {
            std::lock_guard<std::mutex> lock(mock_.mu);
            const bool fresh = mock_.seenIds[mailbox].insert(deliveryId).second;
            if (cls == "content" && fresh) {
                // Consume the presented token: it must be one the mailbox owner
                // registered (else a real server would reject the delivery).
                const std::string tokenB64 = inner.at("token").get<std::string>();
                CHECK(mock_.registered[mailbox].erase(tokenB64) == 1);
                if (mailbox == mock_.watchMailbox
                    && mock_.singletons[mailbox].count(tokenB64) != 0) {
                    mock_.refillUsedPrepaid = true;
                }
            }
            if (fresh) {
                mock_.mailbox[mailbox].push_back(
                    {"m" + std::to_string(mock_.nextId++), cls, payload});
            }
        }
        const Bytes signedBytes(deliveryId.begin(), deliveryId.end());
        const nlohmann::json reply = {
            {"delivered", true},
            {"deliveryId", deliveryId},
            {"signerPub", toBase64(signingKey_.publicDer())},
            {"sig", toBase64(bazarish::sign(signingKey_, signedBytes))},
        };
        return reply.dump() + "\n";
    }

    Mock& mock_;
    const Key& signingKey_;
    std::string written_;
    std::string reply_;
    std::size_t sent_ = 0;
};

}  // namespace

// The stub server these tests talk to is a plain HTTP listener on localhost -
// the same shape as a stand on a LAN, and the reason that switch exists.
int main()
{
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    const Identity serverIdentity = Identity::generate();
    Mock m;
    m.serverFp = serverIdentity.fingerprint();

    http::Server server(localOptions());

    server.get("/v1/messaging/destination",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            std::lock_guard<std::mutex> lock(m.mu);
            respondJson(response,
                {{"dest", m.destFor[caller]}, {"servingKey", toBase64(m.serverSealing.publicDer())}});
        }));

    const auto handlePublishCard
        = [&](const http::Request& request, http::Response& response) {
              const std::string caller = requireCaller(request);
              const std::string cardB64
                  = nlohmann::json::parse(request.body).at("card").get<std::string>();
              // Faithful: verify the user-signed card and keep it verbatim to hand
              // back on a card fetch (the routing + prekey a peer needs).
              const ContactCard card = ContactCard::verify(fromBase64(cardB64));
              CHECK(card.user == caller);
              {
                  std::lock_guard<std::mutex> lock(m.mu);
                  m.certFor[caller] = cardB64;
              }
              // Hex, and different per user: the descriptor codec insists on
              // both, exactly as the real capability does.
              const std::string view = toHex(sha256(Bytes(caller.begin(), caller.end())))
                                           .substr(0, bazarish::kViewCapabilityChars);
              {
                  std::lock_guard<std::mutex> lock(m.mu);
                  m.viewFor[caller] = view;
              }
              respondJson(response, {{"quotaBytes", 100u * 1024 * 1024}, {"view", view}});
          };
    server.post("/v1/account/card", stub(handlePublishCard));

    // Registering delegates this account's offline transient before republishing
    // the card with its routing, so the account API must take one.
    server.post("/v1/account/i2p-dest",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            CHECK(!nlohmann::json::parse(request.body).at("transient").get<std::string>().empty());
            respondJson(response, {{"ok", true}});
        }));

    // Device self-sync: one device writing into its own account's mailbox. No
    // token, no destination - the signature on the request is the whole check.
    server.post("/v1/messaging/self",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const nlohmann::json body = nlohmann::json::parse(request.body);
            std::lock_guard<std::mutex> lock(m.mu);
            m.mailbox[caller].push_back({body.at("deliveryId").get<std::string>(), "device",
                fromBase64(body.at("payload").get<std::string>())});
            respondJson(response, {{"ok", true}});
        }));

    server.post("/v1/messaging/clients",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            respondJson(response, {{"ok", true}});
        }));

    // The card is answered only to a caller that brings back the key from the
    // descriptor, exactly as the node does.
    server.get("/v1/account/card",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            std::lock_guard<std::mutex> lock(m.mu);
            const auto found = m.certFor.find(user);
            if (found == m.certFor.end()) {
                response.status = 404;
                respondJson(response, {{"error", "unknown"}});
                return;
            }
            const ContactCard card = ContactCard::verify(fromBase64(found->second));
            if (toBase64Url(card.servingSealingKeyDer) != request.query("key")) {
                response.status = 404;
                respondJson(response, {{"error", "unknown"}});
                return;
            }
            respondJson(response, {{"user", user}, {"card", found->second}});
        }));

    server.post("/v1/messaging/tokens",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const nlohmann::json tokens = nlohmann::json::parse(request.body).at("tokens");
            std::lock_guard<std::mutex> lock(m.mu);
            for (const nlohmann::json& token : tokens) {
                m.registered[caller].insert(token.get<std::string>());
            }
            // A one-token registration is the prepaid token a low-stash request
            // embeds (issueOneToken); a full batch is 64 of them.
            if (tokens.size() == 1) {
                m.singletons[caller].insert(tokens.at(0).get<std::string>());
            }
            respondJson(response, {{"ok", true}});
        }));

    server.get("/v1/messaging/pending",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            std::lock_guard<std::mutex> lock(m.mu);
            nlohmann::json pending = nlohmann::json::array();
            for (const Mock::Item& item : m.mailbox[caller]) {
                pending.push_back({{"id", item.id}, {"class", item.cls}});
            }
            respondJson(response, {{"pending", pending}});
        }));

    server.get(R"(/v1/messaging/pending/(.+))",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const std::string id = request.captures.at(0);
            std::lock_guard<std::mutex> lock(m.mu);
            for (const Mock::Item& item : m.mailbox[caller]) {
                if (item.id == id) {
                    response.contentType = "application/octet-stream";
                    response.body = std::string(item.payload.begin(), item.payload.end());
                    return;
                }
            }
            response.status = 404;
        }));

    server.post("/v1/messaging/ack",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const std::string blobId
                = nlohmann::json::parse(request.body).at("blobId").get<std::string>();
            std::lock_guard<std::mutex> lock(m.mu);
            std::vector<Mock::Item>& box = m.mailbox[caller];
            box.erase(std::remove_if(box.begin(), box.end(),
                          [&](const Mock::Item& item) { return item.id == blobId; }),
                box.end());
            respondJson(response, {{"ok", true}});
        }));

    const int port = server.start();
    CHECK(port > 0);

    ServerEndpoint endpoint;
    endpoint.serverFingerprint = m.serverFp;
    endpoint.facades = {Facade{false, "127.0.0.1", port, {}}};

    const fs::path aDir = fs::temp_directory_path() / "bz-refill-a";
    const fs::path bDir = fs::temp_directory_path() / "bz-refill-b";
    fs::remove_all(aDir);
    fs::remove_all(bDir);

    // Reported after the accounts are closed and removed.
    int bobSent = 0;
    int aliceSent = 0;

    // Both accounts go once the sessions holding them are gone: an open database
    // file is not one every platform lets go of.
    {
        Session alice = Session::create(aDir, endpoint, std::string{});
        Session bob = Session::create(bDir, endpoint, std::string{});
        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.destFor[alice.fingerprint()] = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            m.destFor[bob.fingerprint()] = "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            // Watch Alice's mailbox: the prepaid-token refill is a content delivery into
            // it that spends one of Alice's own single-registered tokens.
            m.watchMailbox = alice.fingerprint();
        }

        alice.registerAccount();
        bob.registerAccount();

        // A card fetch dials the peer's destination directly over I2P; there is no
        // router here, so the harness stands in for that dial. It answers exactly as
        // a serving destination does: the card when the query brings back the view
        // capability, and the same nothing otherwise.
        const auto directDial = [&m](const std::string& toDest, const std::string& op,
                                    const Bytes& query) {
            CHECK(op == "card");
            (void)toDest;
            const CardFetchQuery asked = cardFetchQueryFromJson(nlohmann::json::parse(query));
            std::lock_guard<std::mutex> lock(m.mu);
            const auto found = m.certFor.find(asked.fingerprint);
            FetchOutcome outcome;
            if (found == m.certFor.end() || asked.view != m.viewFor[asked.fingerprint]) {
                outcome.errorCode = "CARD_UNKNOWN";
                return outcome;
            }
            outcome.ok = true;
            outcome.sealed = fromBase64(found->second);
            return outcome;
        };
        alice.setFetchTransport(directDial);
        bob.setFetchTransport(directDial);

        // Outgoing mail leaves the client itself, so the harness stands in for the
        // dial as well: every delivery reaches the mock server above over the real
        // frame, with no router and no waiting.
        const Key ackSigning = Key::generateSigning();
        const auto courierFor = [&m, &ackSigning]() {
            return std::make_unique<OutboundCourier>([](const std::string&, const std::string&) { return true; },
                [&m, &ackSigning](const std::string&,
                    std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                    return std::make_shared<MockServerStream>(m, ackSigning);
                });
        };
        alice.setOutboundCourier(courierFor());
        bob.setOutboundCourier(courierFor());

        // Establish the contact both ways: Alice adds Bob from his invite (the only
        // way in - a bare fingerprint would need a server to say who it hosts), Bob
        // accepts. Now Alice holds a batch of Bob's tokens and Bob holds a batch of
        // Alice's.
        alice.addByInvite(bob.inviteUri(), "hi bob");
        bob.sync();
        bob.acceptContactRequest(alice.fingerprint());
        alice.sync();
        CHECK(alice.hasContact(bob.fingerprint()));
        CHECK(bob.hasContact(alice.fingerprint()));

        // A batch that was addressed to nobody is not kept whole: each device takes
        // one token out of it and spends that on a batch addressed to itself, so no
        // two devices of an account hold the same one-time tokens. Two rounds of
        // sync carry those requests and their answers.
        for (int round = 0; round < 2; ++round) {
            alice.sync();
            bob.sync();
        }
        CHECK(alice.hasContact(bob.fingerprint()));
        CHECK(bob.hasContact(alice.fingerprint()));

        // The connection log: what the account did on the wire, which is the one
        // place a user can see a delivery nobody signed for. One send has to
        // leave three marks - the send itself, the far side's answer, and the
        // server call underneath - and the receiving side has to see the arrival.
        {
            const auto logHas = [](const std::vector<WireEvent>& events,
                                    const std::string& whatPrefix, const std::string& status) {
                for (const WireEvent& event : events) {
                    if (event.what.rfind(whatPrefix, 0) == 0
                        && (status.empty() || event.status == status)) {
                        return true;
                    }
                }
                return false;
            };
            alice.sendMessage(bob.fingerprint(), "logged");
            bool stored = false;
            for (int round = 0; round < 20 && !stored; ++round) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                stored = logHas(alice.connectionLog(), "text to", "stored");
            }
            const std::vector<WireEvent> aliceLog = alice.connectionLog();
            CHECK(logHas(aliceLog, "text to", "sending"));
            CHECK(stored);
            // The account's own server, spoken to over HTTP: its status is the
            // only confirmation this side gets for what it uploaded.
            CHECK(logHas(aliceLog, "POST /v1/messaging/", "200"));
            // Nothing here may carry what was written.
            for (const WireEvent& event : aliceLog) {
                CHECK(event.what.find("logged") == std::string::npos);
                CHECK(event.detail.find("logged") == std::string::npos);
            }
            bob.sync();
            CHECK(logHas(bob.connectionLog(), "text from", {}));
            // A self-message names the kind it carries; the sealed payload cannot.
            alice.setDisplayName("Alice of the log");
            CHECK(logHas(alice.connectionLog(), "self device.account-name", "sending"));
        }

        // An interactive message: the buttons a bot attaches ride on an ordinary
        // text message, and the far side has to be handed them as their wire form.
        // Checked here because a keyboard that goes missing between the two shows
        // up as a bot whose buttons simply are not there.
        {
            const InlineKeyboard keyboard{
                {{"Ping", "ping", {}}, {"Time", "time", {}}},
                {{"Help", {}, "help"}},
            };
            alice.sendInteractive(bob.fingerprint(), "pick one", keyboard);
            std::string received;
            for (int round = 0; round < 3 && received.empty(); ++round) {
                for (const IncomingMessage& item : bob.sync()) {
                    if (item.contentType == "text" && item.text == "pick one") {
                        received = item.keyboardJson;
                    }
                }
            }
            CHECK(!received.empty());
            const nlohmann::json rows = nlohmann::json::parse(received);
            CHECK(rows.is_array() && rows.size() == 2);
            CHECK(rows.at(0).size() == 2);
            CHECK(rows.at(0).at(0).at("text") == "Ping");
            CHECK(rows.at(0).at(0).at("data") == "ping");
            CHECK(rows.at(1).at(0).at("command") == "help");
        }

        // Asking to be topped up without a message to carry the ask: what a
        // service that posts notices does while the other side is about. The ask
        // is consumed silently and answered with a batch.
        {
            const std::size_t before = alice.sendCapacity(bob.fingerprint());
            alice.requestTokens(bob.fingerprint());
            for (int round = 0; round < 3; ++round) {
                for (const IncomingMessage& item : bob.sync()) {
                    // Nothing about it is shown: it is not a line of anything.
                    CHECK(item.contentType != "unsupported");
                }
                alice.sync();
            }
            const std::size_t after = alice.sendCapacity(bob.fingerprint());
            // One token went on the ask, a batch came back.
            CHECK(after > before);
        }

        const auto rejects = [](const auto& fn) {
            try {
                fn();
            } catch (const std::exception&) {
                return true;
            }
            return false;
        };

        // Drain Bob's stash of Alice's tokens to EMPTY. Alice does NOT sync in between, so
        // she never sees Bob's low-stash signal and never refills him: Bob ends holding
        // none of Alice's tokens.
        while (!rejects([&]() { bob.sendMessage(alice.fingerprint(), "b->a " + std::to_string(bobSent)); })) {
            ++bobSent;
        }
        CHECK(bobSent > 0);
        // Confirm the stash is truly empty: another send is rejected up front.
        CHECK(rejects([&]() { bob.sendMessage(alice.fingerprint(), "overflow"); }));

        // Drain Alice's stash too. Her low-stash sends embed a fresh prepaid token each
        // (registered one-at-a-time with her own server); she ends empty as well.
        while (!rejects([&]() { alice.sendMessage(bob.fingerprint(), "a->b " + std::to_string(aliceSent)); })) {
            ++aliceSent;
        }
        CHECK(aliceSent > 0);
        CHECK(rejects([&]() { alice.sendMessage(bob.fingerprint(), "overflow"); }));

        // Bob syncs: he processes Alice's stream (the tail carries lowStash + refillToken)
        // and must reply with a token-refill. He holds NONE of Alice's tokens, so the only
        // way that reply can be delivered is by spending the prepaid token Alice embedded.
        // Without the prepaid mechanism sendTokenRefill would bail on the empty stash.
        bob.sync();
        CHECK(waitFor([&m]() {
            std::lock_guard<std::mutex> lock(m.mu);
            return m.refillUsedPrepaid;
        }));

        // Alice syncs: she applies Bob's fresh batch, so her stash is replenished.
        bool gotRefill = false;
        for (const IncomingMessage& message : alice.sync()) {
            if (message.contentType == "token-refill") {
                gotRefill = true;
            }
        }
        CHECK(gotRefill);

        // Proof the refill actually restored Alice's sending capacity: she was empty, yet
        // can send again now (this would throw "out of delivery tokens" otherwise).
        alice.sendMessage(bob.fingerprint(), "after refill");

        // A refill is asked for by whatever is being sent, not by a message the
        // user typed: the ask rides on the same envelope as the content, and
        // every kind goes out through one path. Spend down with one kind at a
        // time and watch the capacity come back up - only that kind can have
        // asked for it. The bound is well past a batch, so a kind that never
        // asks runs out instead of looping.
        {
            const auto refillsWith = [&](const std::function<void()>& send) {
                constexpr int kBoundedTries = 200;
                for (int i = 0; i < kBoundedTries; ++i) {
                    const std::size_t before = alice.sendCapacity(bob.fingerprint());
                    try {
                        send();
                    } catch (const std::exception& error) {
                        // Running dry is the failure this checks for: a kind that
                        // never asks for a refill spends the last token and stops.
                        std::fprintf(stderr, "send stopped after %d: %s\n", i, error.what());
                        return false;
                    }
                    bob.sync();
                    alice.sync();
                    if (alice.sendCapacity(bob.fingerprint()) > before) {
                        return true;
                    }
                }
                return false;
            };
            const std::string ref = toHex(randomBytes(8));
            // An ordinary content kind that is not text.
            CHECK(refillsWith([&]() { alice.sendReaction(bob.fingerprint(), ref, "\xf0\x9f\x91\x8d"); }));
            // The one path that deliberately does not establish a dialog: a
            // receipt still has to keep its own sending capacity alive.
            CHECK(refillsWith([&]() { alice.sendReceipt(bob.fingerprint(), ref); }));
            // A kind with no bubble of its own: it acts on a message already sent.
            CHECK(refillsWith([&]() { alice.sendDelete(bob.fingerprint(), ref); }));
        }

        // Removing an avatar travels like setting one. Bob holds Alice's until she
        // takes it back; a removal that is never sent would leave him holding it for
        // good, which is what used to happen.
        {
            const Bytes face = {0xFF, 0xD8, 0xFF, 0xE0, 'j', 'p', 'g'};
            alice.setAvatar(face, "image/jpeg");
            bob.sync();
            CHECK(bob.contactAvatar(alice.fingerprint()) == face);

            alice.setAvatar({}, {});
            CHECK(alice.avatar().empty());
            bob.sync();
            CHECK(bob.contactAvatar(alice.fingerprint()).empty());
        }

        // --- The saved chat ---
        //
        // Addressed to herself, a message is kept rather than delivered: no token
        // is spent, nothing is dialled, and it goes to her own mailbox for her
        // other devices to pick up.
        {
            const std::size_t before = alice.sendCapacity(bob.fingerprint());
            alice.sendMessage(alice.fingerprint(), "note to self");
            CHECK(alice.sendCapacity(bob.fingerprint()) == before);

            // It went into her own mailbox as a device notice, for her other
            // devices to pick up.
            std::size_t deviceItems = 0;
            {
                std::lock_guard<std::mutex> lock(m.mu);
                for (const Mock::Item& item : m.mailbox[alice.fingerprint()]) {
                    deviceItems += item.cls == "device" ? 1 : 0;
                }
            }
            CHECK(deviceItems >= 1);

            // And what another device does with one: the same line, in the same
            // chat, as one of her own. Built here as the wire carries it, under
            // another device id - the device that saved it skips its own echo.
            const nlohmann::json saved = {
                {"v", 1},
                {"type", "device.saved"},
                {"id", "saved-1"},
                {"from", alice.fingerprint()},
                {"sentAt", 1},
                {"device", "someotherdevice"},
                {"message",
                    {
                        {"v", 1},
                        {"type", "text"},
                        {"id", "kept-1"},
                        {"from", alice.fingerprint()},
                        {"sentAt", 1},
                        {"text", "note to self"},
                    }},
            };
            {
                // The wire carries CBOR, which is what the reader expects.
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice.fingerprint()].push_back({"saved-echo", "device",
                    cms::seal(nlohmann::json::to_cbor(saved),
                        Key::fromPublicDer(fromBase64(alice.sealingPublicB64())))});
            }
            bool sawSaved = false;
            for (const IncomingMessage& item : alice.sync()) {
                if (item.fromFingerprint == alice.fingerprint() && item.text == "note to self") {
                    sawSaved = true;
                    CHECK(item.sentByUs);
                }
            }
            CHECK(sawSaved);

            // A file has no bytes to fetch on another device, so it is refused.
            bool refused = false;
            try {
                alice.sendFile(alice.fingerprint(), aDir / "meta", "", {}, "");
            } catch (const std::exception&) {
                refused = true;
            }
            CHECK(refused);
        }

        // --- The one name a contact may not have ---
        {
            alice.renameContact(bob.fingerprint(), "Saved messages");
            CHECK(alice.contactDisplayName(bob.fingerprint()) == "(Contact) Saved messages");
            alice.renameContact(bob.fingerprint(), "  saved MESSAGES  ");
            CHECK(alice.contactDisplayName(bob.fingerprint()) == "(Contact)   saved MESSAGES  ");
            alice.renameContact(bob.fingerprint(), "Bob");
            CHECK(alice.contactDisplayName(bob.fingerprint()) == "Bob");
        }

        // --- Per-contact switches ---
        {
            CHECK(alice.contactCalls(bob.fingerprint()));
            CHECK(alice.contactNotifications(bob.fingerprint()));
            alice.setContactCalls(bob.fingerprint(), false);
            alice.setContactNotifications(bob.fingerprint(), false);
            CHECK(!alice.contactCalls(bob.fingerprint()));
            CHECK(!alice.contactNotifications(bob.fingerprint()));
            alice.setContactCalls(bob.fingerprint(), true);
            alice.setContactNotifications(bob.fingerprint(), true);
        }

        // --- Blocking ---
        //
        // What a block means where the message is read: Bob still holds tokens and
        // still delivers, and none of it reaches her.
        {
            bob.sendMessage(alice.fingerprint(), "before the block");
            alice.setBlocked(bob.fingerprint(), true);
            CHECK(alice.isBlocked(bob.fingerprint()));
            CHECK(alice.blockedPeers().size() == 1);

            bob.sendMessage(alice.fingerprint(), "after the block");
            bool heardBlocked = false;
            for (const IncomingMessage& item : alice.sync()) {
                if (item.text == "after the block") {
                    heardBlocked = true;
                }
            }
            CHECK(!heardBlocked);
            // Her own mailbox is not left holding it either: it was acked away.
            {
                std::lock_guard<std::mutex> lock(m.mu);
                CHECK(m.mailbox[alice.fingerprint()].empty());
            }

            // And she cannot write to them while the block stands.
            bool sendRefused = false;
            try {
                alice.sendMessage(bob.fingerprint(), "still there?");
            } catch (const std::exception&) {
                sendRefused = true;
            }
            CHECK(sendRefused);

            // Lifting the block gives back what it took away: blocking revoked the
            // tokens Bob held, so the first thing Alice writes to him carries a
            // fresh batch and he can answer at once.
            // What a batch looks like from outside the core: many tokens at once,
            // as against the one a low-stash signal prepays.
            constexpr std::size_t kBatchAtLeast = 16;
            const std::size_t bobHeld = bob.sendCapacity(alice.fingerprint());
            const auto minted = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.registered[alice.fingerprint()].size();
            };
            const std::size_t before = minted();
            alice.setBlocked(bob.fingerprint(), false);
            CHECK(!alice.isBlocked(bob.fingerprint()));
            alice.sendMessage(bob.fingerprint(), "you can write to me again");
            // A whole batch was minted and registered for him, and it rode on that
            // one message rather than on an errand of its own.
            CHECK(minted() - before >= kBatchAtLeast);

            // The next message is an ordinary one: the batch is not handed out again.
            const std::size_t afterBatch = minted();
            alice.sendMessage(bob.fingerprint(), "and this one is just a message");
            CHECK(minted() - afterBatch < kBatchAtLeast);

            // And what he already held was not thrown away by it.
            bob.sync();
            CHECK(bob.sendCapacity(alice.fingerprint()) >= bobHeld);

            bob.sendMessage(alice.fingerprint(), "after the unblock");
            bool heardAgain = false;
            for (const IncomingMessage& item : alice.sync()) {
                if (item.text == "after the unblock") {
                    heardAgain = true;
                }
            }
            CHECK(heardAgain);
        }

        // --- What another device of ours says, and what this one does with it ---
        //
        // Each notice is built as the wire carries it, under another device id,
        // and handed to her: what matters is that it is applied here.
        {
            const auto fromAnotherDevice = [&](const nlohmann::json& notice) {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice.fingerprint()].push_back({"self-" + notice.at("id").get<std::string>(),
                    "device",
                    cms::seal(nlohmann::json::to_cbor(notice),
                        Key::fromPublicDer(fromBase64(alice.sealingPublicB64())))});
            };
            const auto notice = [&](const std::string& type, nlohmann::json extra) {
                extra["v"] = 1;
                extra["type"] = type;
                extra["id"] = type;
                extra["from"] = alice.fingerprint();
                extra["sentAt"] = 1;
                extra["device"] = "someotherdevice";
                return extra;
            };

            // The account was renamed there.
            CHECK(alice.displayName() != "renamed elsewhere");
            fromAnotherDevice(notice("device.account-name", {{"name", "renamed elsewhere"}}));
            alice.sync();
            CHECK(alice.displayName() == "renamed elsewhere");

            // It stopped taking calls there, and stopped telling correspondents
            // when it reads them.
            CHECK(alice.acceptCalls());
            CHECK(alice.sendReceipts());
            fromAnotherDevice(notice("device.account-prefs",
                {{"acceptCalls", false}, {"sendReceipts", false}}));
            alice.sync();
            CHECK(!alice.acceptCalls());
            CHECK(!alice.sendReceipts());
            // A notice that says nothing about one of them leaves it alone.
            fromAnotherDevice(notice("device.account-prefs", {{"acceptCalls", true}}));
            alice.sync();
            CHECK(alice.acceptCalls());
            CHECK(!alice.sendReceipts());
            alice.setSendReceipts(true);

            // A contact's switches were changed there.
            fromAnotherDevice(notice("device.contact-prefs",
                {{"peer", bob.fingerprint()}, {"notifications", false}, {"allowCalls", false}}));
            alice.sync();
            CHECK(!alice.contactNotifications(bob.fingerprint()));
            CHECK(!alice.contactCalls(bob.fingerprint()));

            // Somebody was blocked there.
            const std::string stranger = std::string(52, 'y');
            fromAnotherDevice(notice("device.contact-block",
                {{"peer", stranger}, {"blocked", true}}));
            alice.sync();
            CHECK(alice.isBlocked(stranger));
            fromAnotherDevice(notice("device.contact-block",
                {{"peer", stranger}, {"blocked", false}}));
            alice.sync();
            CHECK(!alice.isBlocked(stranger));

            // A conversation was emptied there: the core hands it to the interface
            // to wipe, and says which one.
            fromAnotherDevice(notice("device.chat-clear", {{"peer", bob.fingerprint()}}));
            bool sawClear = false;
            for (const IncomingMessage& item : alice.sync()) {
                if (item.contentType == "device.chat-clear") {
                    sawClear = true;
                    CHECK(item.refId == bob.fingerprint());
                }
            }
            CHECK(sawClear);

            // And a contact was removed there.
            CHECK(alice.hasContact(bob.fingerprint()));
            fromAnotherDevice(notice("device.contact-remove", {{"peer", bob.fingerprint()}}));
            bool sawRemove = false;
            for (const IncomingMessage& item : alice.sync()) {
                if (item.contentType == "device.contact-remove") {
                    sawRemove = true;
                    CHECK(item.refId == bob.fingerprint());
                }
            }
            CHECK(sawRemove);
            CHECK(!alice.hasContact(bob.fingerprint()));
        }

        // --- A stranger writing content ---
        //
        // Nobody without a contact row may put a message in front of the user; the
        // item is consumed where it is read, and no contact is created for them.
        {
            const std::string stranger = std::string(52, 'z');
            const nlohmann::json inner = {
                {"v", 1},
                {"type", "text"},
                {"id", "stranger-1"},
                {"from", stranger},
                {"sentAt", 1},
                {"text", "let me in"},
            };
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice.fingerprint()].push_back({"stranger-blob", "content",
                    cms::seal(nlohmann::json::to_cbor(inner),
                        Key::fromPublicDer(fromBase64(alice.sealingPublicB64())))});
            }
            for (const IncomingMessage& item : alice.sync()) {
                CHECK(item.fromFingerprint != stranger);
            }
            CHECK(!alice.hasContact(stranger));
        }
    }

    server.stop();
    fs::remove_all(aDir);
    fs::remove_all(bDir);

    std::fprintf(stderr, "TestTokenRefill passed (bob sent %d, alice sent %d)\n", bobSent, aliceSent);
    return 0;
}
