// Bazarish project (c) 2026
#include "Client.hpp"
#include "OutboundCourier.hpp"
#include "Session.hpp"

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
                const std::string hashB64
                    = toBase64(deliveryTokenHash(fromBase64(inner.at("token").get<std::string>())));
                CHECK(mock_.registered[mailbox].erase(hashB64) == 1);
                if (mailbox == mock_.watchMailbox
                    && mock_.singletons[mailbox].count(hashB64) != 0) {
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
            const nlohmann::json hashes = nlohmann::json::parse(request.body).at("hashes");
            std::lock_guard<std::mutex> lock(m.mu);
            for (const nlohmann::json& hash : hashes) {
                m.registered[caller].insert(hash.get<std::string>());
            }
            // A one-hash registration is the prepaid token a low-stash request embeds
            // (issueOneToken); a full batch is 64 hashes.
            if (hashes.size() == 1) {
                m.singletons[caller].insert(hashes.at(0).get<std::string>());
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
    }

    server.stop();
    fs::remove_all(aDir);
    fs::remove_all(bDir);

    std::fprintf(stderr, "TestTokenRefill passed (bob sent %d, alice sent %d)\n", bobSent, aliceSent);
    return 0;
}
