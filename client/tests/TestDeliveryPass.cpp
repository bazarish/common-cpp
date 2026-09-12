// Bazarish project (c) 2026
#include "Client.hpp"
#include "OutboundCourier.hpp"
#include "AccountDb.hpp"
#include "Authorship.hpp"
#include "Session.hpp"
#include "WireLog.hpp"

#include "TunnelStub.hpp"

#include <bazarish/AliasMaintenance.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/Padding.hpp>
#include <bazarish/Pass.hpp>

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


// Who the tunnel said this is. The transport authenticates the caller once, when
// it opens; a route behind it is told, exactly as the real server tells one from
// the session it holds.
std::string requireCaller(const http::Request& request)
{
    const std::string caller = request.header(bazarish::teststub::kCallerHeader);
    if (caller.empty()) {
        throw std::runtime_error("no caller: this request did not come through the tunnel");
    }
    return caller;
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
    // Every route here locks one mutex, and the tunnel means each client holds a
    // connection for a whole exchange: with the default four, five accounts and
    // their couriers can occupy every thread and wait on each other.
    options.threads = 16;
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
// Where the name service answers in this test, standing in for the address baked
// into a release build.
constexpr const char* kResolverDest
    = "flkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";

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
    // Owner fp -> the pass handles that mailbox admits. Handles, not passes: the
    // sender presents the pass and this is what a server holds.
    std::map<std::string, std::set<std::string>> registered;
    std::map<std::string, std::set<std::string>> seenIds;  // recipient fp -> admitted deliveryIds
    // The biggest tokenless request this server was ever handed: what the
    // protocol cap has to be, and no more.
    std::size_t largestContactRequest = 0;
    int nextId = 1;
    // What the far side answers instead of "delivered", when a test wants to see
    // what a client does with a refusal. Empty means it accepts, as before.
    std::string refuseWith;
    // A serving-key rotation in two steps: the server mints the pair, the client
    // signs a card over it, and only the commit puts it in force.
    std::map<std::string, std::string> pendingView;  // fingerprint -> view minted, not yet in force
    // The central name registry, as far as this test is concerned: who owns a
    // name, and where it currently says that name is answered.
    std::map<std::string, std::string> aliasOwner;       // alias -> owner fingerprint
    std::map<std::string, Descriptor> aliasDescriptor;   // alias -> binding
    int resolverStatusCalls = 0;
    int resolverUpdateCalls = 0;
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
// the frame the courier really writes, unseals the envelope, checks the pass the
// way a delivery engine does, and signs the confirmation the same way -
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
            if (!mock_.refuseWith.empty()) {
                // Refused before anything is stored, the way a server refuses a
                // pass it does not know.
                const nlohmann::json refusal = {{"delivered", false},
                    {"errorCode", mock_.refuseWith}, {"errorMessage", "refused by the test"}};
                return refusal.dump() + "\n";
            }
            const bool fresh = mock_.seenIds[mailbox].count(deliveryId) == 0;
            if (cls == "content" && fresh) {
                // The pass presented must be one this mailbox admits - and it is
                // still admitted afterwards. Nothing is taken here, and that is
                // the whole change: what used to be a one-time capability is now
                // a standing one, so the same value carries every message this
                // test sends.
                const Bytes presented = fromBase64(inner.at("pass").get<std::string>());
                if (mock_.registered[mailbox].count(toBase64(deliveryPassHandle(presented)))
                    != 1) {
                    // A pass this mailbox does not hold is refused, and nothing
                    // is written down about the attempt - the way a revoked
                    // correspondent is turned away.
                    const nlohmann::json refusal = {{"delivered", false},
                        {"errorCode", "DELIVERY_REJECTED"},
                        {"errorMessage", "delivery rejected"}};
                    return refusal.dump() + "\n";
                }
            }
            if (cls == "contact") {
                mock_.largestContactRequest
                    = std::max(mock_.largestContactRequest, payload.size());
            }
            if (fresh) {
                mock_.seenIds[mailbox].insert(deliveryId);
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
              CHECK(card.fingerprint() == caller);
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

    // Rotating the serving key: the server mints a fresh pair and holds the new
    // capability aside until the client commits a card signed over it.
    server.post("/v1/account/serving-key",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            // A fresh capability of the full width, as a real server mints: a
            // short one is not a capability at all and the client would refuse to
            // publish it, which would make the check below pass for nothing.
            const std::string view = toHex(randomBytes(bazarish::kViewCapabilityBytes));
            CHECK(isViewCapability(view));
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.pendingView[caller] = view;
            }
            respondJson(response,
                {{"servingKey", toBase64(m.serverSealing.publicDer())}, {"view", view}});
        }));
    server.post("/v1/account/serving-key/commit",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const std::string cardB64
                = nlohmann::json::parse(request.body).at("card").get<std::string>();
            CHECK(ContactCard::verify(fromBase64(cardB64)).fingerprint() == caller);
            std::lock_guard<std::mutex> lock(m.mu);
            m.certFor[caller] = cardB64;
            m.viewFor[caller] = m.pendingView[caller];
            respondJson(response, {{"ok", true}});
        }));

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

    server.post("/v1/messaging/passes",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const nlohmann::json passes = nlohmann::json::parse(request.body).at("passes");
            std::lock_guard<std::mutex> lock(m.mu);
            for (const nlohmann::json& handle : passes) {
                m.registered[caller].insert(handle.get<std::string>());
            }
            respondJson(response, {{"ok", true}, {"held", m.registered[caller].size()}});
        }));

    server.post("/v1/messaging/passes/revoke",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const nlohmann::json passes = nlohmann::json::parse(request.body).at("passes");
            std::lock_guard<std::mutex> lock(m.mu);
            std::size_t dropped = 0;
            for (const nlohmann::json& handle : passes) {
                dropped += m.registered[caller].erase(handle.get<std::string>());
            }
            respondJson(response, {{"revoked", dropped}});
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

    // The stub speaks the tunnel, because that is the only transport a client
    // has: one sealed path in, sealed frames out, and these routes behind it.
    const Identity stubServerIdentity = Identity::generate();
    const Key stubServerSealing = Key::generateSealing();
    bazarish::teststub::Tunnel tunnelStub(server, stubServerIdentity, stubServerSealing);
    const int port = server.start();
    CHECK(port > 0);

    ServerEndpoint endpoint;
    endpoint.serverFingerprint = stubServerIdentity.fingerprint();
    endpoint.facades = {Facade{false, "127.0.0.1", port, {}}};

    // The name service this build talks to: an offline root, a delegated signing
    // key under it, and an address. A release bakes the first and third in; a test
    // hands them over the environment, which is read when a session is opened, so
    // this has to happen before any account exists.
    const Identity resolverRoot = Identity::generate();
    const Identity resolverDelegated = Identity::generate();
    const Bytes resolverDelegationDer = DelegationCertificate::issue(resolverRoot,
        resolverDelegated, static_cast<std::int64_t>(std::time(nullptr)) - 60,
        static_cast<std::int64_t>(std::time(nullptr)) + 30 * 24 * 3600);
    ::setenv("BAZARISH_RESOLVER_ROOT", resolverRoot.fingerprint().c_str(), 1);
    ::setenv("BAZARISH_RESOLVER_DEST", kResolverDest, 1);

    const fs::path aDir = fs::temp_directory_path() / "bz-pass-a";
    const fs::path bDir = fs::temp_directory_path() / "bz-pass-b";
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
        // Alice's own signing key, read the way another device of hers would
        // hold it: an envelope injected below has to be signed like a real one.
        const Identity aliceIdentity
            = Identity::fromPrivatePem(AccountDb(aDir, std::string{}).text("identity.pem"));
        // A backup taken before she had anybody: restored later, it is a device
        // that holds the account and knows nobody, which is the case the address
        // book exists for.
        const fs::path earlyBundle = fs::temp_directory_path() / "bz-pass-early.bundle";
        fs::remove(earlyBundle);
        alice.exportAccount(earlyBundle, "bundle-password");
        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.destFor[alice.fingerprint()] = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            m.destFor[bob.fingerprint()] = "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
        }

        // A switched-off account announces nothing, itself included.
        alice.setSwitchedOff(true);
        bool announceRefused = false;
        try {
            alice.registerAccount();
        } catch (const std::exception&) {
            announceRefused = true;
        }
        CHECK(announceRefused);
        alice.setSwitchedOff(false);

        alice.registerAccount();
        bob.registerAccount();

        // A card fetch dials the peer's destination directly over I2P; there is no
        // router here, so the harness stands in for that dial. It answers exactly as
        // a serving destination does: the card when the query brings back the view
        // capability, and the same nothing otherwise.
        const auto directDial = [&m, &resolverRoot, &resolverDelegated, &resolverDelegationDer](
                                    const std::string& toDest, const std::string& op,
                                    const Bytes& query) {
            // The central resolver answers on the same dial. Its ops are signed by
            // the owner, and its answers are signed by its delegated key.
            if (op == kAliasStatusOp || op == kAliasUpdateOp) {
                CHECK(toDest == kResolverDest);
                FetchOutcome outcome;
                const VerifiedAliasRequest asked = verifyAliasMaintenanceRequest(
                    query, static_cast<std::int64_t>(std::time(nullptr)));
                CHECK(asked.request.op == op);
                std::lock_guard<std::mutex> lock(m.mu);
                const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
                if (op == kAliasUpdateOp) {
                    ++m.resolverUpdateCalls;
                    const auto owner = m.aliasOwner.find(asked.request.alias);
                    if (owner == m.aliasOwner.end() || owner->second != asked.owner) {
                        outcome.errorCode = "NOT_OWNER";
                        return outcome;
                    }
                    CHECK(asked.request.descriptor.fingerprint == asked.owner);
                    m.aliasDescriptor[asked.request.alias] = asked.request.descriptor;
                    outcome.ok = true;
                    return outcome;
                }
                ++m.resolverStatusCalls;
                AliasStatus status;
                status.owner = asked.owner;
                for (const auto& [alias, owner] : m.aliasOwner) {
                    if (owner == asked.owner) {
                        status.names.push_back(AliasStatusEntry{alias, now + 365 * 24 * 3600});
                    }
                }
                status.issuedAt = now;
                status.notAfter = now + kAliasStatusValiditySeconds;
                const ResolveResponse answer{
                    signAliasStatus(status, resolverDelegated), resolverDelegationDer};
                const std::string json = toJson(answer).dump();
                outcome.ok = true;
                outcome.sealed = Bytes(json.begin(), json.end());
                return outcome;
            }
            CHECK(op == "card");
            (void)toDest;
            (void)resolverRoot;
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
        // accepts. Now each holds the other's delivery pass.
        alice.addByInvite(bob.inviteUri(), "hi bob");
        bob.sync();
        bob.acceptContactRequest(alice.fingerprint());
        alice.sync();
        CHECK(alice.hasContact(bob.fingerprint()));
        CHECK(bob.hasContact(alice.fingerprint()));

        // The acceptance leaves on the courier's thread, so this waits for it
        // rather than assuming it has landed.
        CHECK(waitFor([&]() {
            alice.sync();
            return alice.canWriteTo(bob.fingerprint());
        }));

        // --- The account's own name in the central registry -------------------
        // A client that knows of no name of its own tells the name service
        // nothing, on any schedule: this is the whole of the quiet case.
        CHECK(alice.aliasNames().empty());
        alice.serviceAliases();
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.resolverStatusCalls == 0);
            CHECK(m.resolverUpdateCalls == 0);
        }

        // Alice bought a name in the browser; the registry knows it, this client
        // does not. Activation is the one way in.
        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasOwner["alice"] = alice.fingerprint();
        }
        CHECK(alice.refreshAliasStatus());
        CHECK(alice.aliasNames().size() == 1);
        CHECK(alice.aliasNames().front().alias == "alice");

        // Knowing the name, it repoints the registry at where this account
        // actually answers.
        CHECK(alice.aliasUpdatePending());
        alice.serviceAliases();
        CHECK(!alice.aliasUpdatePending());
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.at("alice").fingerprint == alice.fingerprint());
            CHECK(m.aliasDescriptor.at("alice").view == m.viewFor[alice.fingerprint()]);
        }

        // THE REGRESSION THIS WHOLE PATH EXISTS FOR: rotating the serving key
        // retires the capability the registry holds. Before, the name went on
        // pointing at a capability the server had stopped honouring and simply
        // stopped working, silently. Now the rotation tells the registry.
        const std::string viewBefore = m.viewFor[alice.fingerprint()];
        alice.rotateServingKey(nullptr);
        const std::string viewAfter = m.viewFor[alice.fingerprint()];
        CHECK(viewAfter != viewBefore);
        CHECK(!alice.aliasUpdatePending());
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.at("alice").view == viewAfter);
        }

        // A name somebody else owns is not repointed by asking nicely.
        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasOwner["bob"] = bob.fingerprint();
        }
        CHECK(bob.aliasNames().empty());
        // Bob never activated, so his rotation asks once - the safety net - and
        // finds the name he did buy, then points it at himself.
        const int statusBefore = m.resolverStatusCalls;
        bob.rotateServingKey(nullptr);
        CHECK(m.resolverStatusCalls == statusBefore + 1);
        CHECK(bob.aliasNames().size() == 1);
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.at("bob").fingerprint == bob.fingerprint());
            CHECK(m.aliasDescriptor.at("alice").fingerprint == alice.fingerprint());
        }
        CHECK(bob.canWriteTo(alice.fingerprint()));
        // One pass each way, and one is all there will ever be: this is the count
        // that used to grow by 256 on every refill.
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.registered[alice.fingerprint()].size() == 1);
            CHECK(m.registered[bob.fingerprint()].size() == 1);
        }

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
            // A self-message names the kind it carries on the call that carries
            // it: from the outside every one of them is the same POST, and a
            // line of its own would have no status to report.
            alice.setDisplayName("Alice of the log");
            CHECK(logHas(alice.connectionLog(),
                "POST /v1/messaging/self (device.account-name)", "200"));
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

        // Nothing runs a pass down, so there is nothing to ask for and nothing to
        // wait on. Send far past what a batch of 256 one-time tokens used to buy
        // and the same value still carries every one of them - and the mailbox
        // that admits them still holds exactly one.
        {
            constexpr int kFarPastABatch = 400;
            for (int i = 0; i < kFarPastABatch; ++i) {
                alice.sendMessage(bob.fingerprint(), "a->b " + std::to_string(aliceSent));
                ++aliceSent;
                bob.sendMessage(alice.fingerprint(), "b->a " + std::to_string(bobSent));
                ++bobSent;
            }
            CHECK(alice.canWriteTo(bob.fingerprint()));
            CHECK(bob.canWriteTo(alice.fingerprint()));
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.registered[alice.fingerprint()].size() == 1);
            CHECK(m.registered[bob.fingerprint()].size() == 1);
        }
        alice.sync();
        bob.sync();

        // What the recipient's server measures is a step, not the message. Two
        // texts of very different length must weigh the same on the wire: the
        // authorship block is a fixed weight, so without padding the remainder
        // would be the message itself - and for text, the number of bytes typed.
        {
            const auto weighOf = [&](const std::string& text) {
                const std::size_t before = [&]() {
                    std::lock_guard<std::mutex> lock(m.mu);
                    return m.mailbox[bob.fingerprint()].size();
                }();
                alice.sendMessage(bob.fingerprint(), text);
                CHECK(waitFor([&]() {
                    std::lock_guard<std::mutex> lock(m.mu);
                    return m.mailbox[bob.fingerprint()].size() > before;
                }));
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[bob.fingerprint()].back().payload.size();
            };
            // What is left is the seal's own DER framing, which wobbles by a
            // byte or two from one seal to the next whatever is inside it - so
            // the same text twice spreads as much as two different texts do.
            // That is the residual, and it carries nothing about the message.
            constexpr std::size_t kSealFramingWobble = 8;
            const std::size_t small = weighOf("hi");
            const std::size_t again = weighOf("hi");
            const std::size_t large = weighOf(std::string(200, 'x'));
            const auto near = [](const std::size_t a, const std::size_t b) {
                return a < b ? b - a <= kSealFramingWobble : a - b <= kSealFramingWobble;
            };
            CHECK(near(small, again));
            CHECK(near(small, large));
        }
        bob.sync();

        // A routing push carries a routing block and nothing else. It is applied
        // like the one on any other message and shows nothing - but it has to be
        // named on arrival, or it falls through to "unsupported", which is what a
        // client says about a message it cannot read.
        {
            CHECK(alice.pushRoutingToContacts({}).told > 0);
            // The push leaves on the courier's thread, so this waits for it
            // rather than assuming one sync is late enough to see it.
            bool sawRouting = false;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob.sync()) {
                    CHECK(item.contentType != "unsupported");
                    if (item.contentType == "contact.routing") {
                        sawRouting = true;
                    }
                }
                return sawRouting;
            }));
        }

        // Every content kind goes out the same way, and none of them has a price
        // to run out of. What used to be checked here - that each kind asks for a
        // refill before its stash empties - is a question that no longer exists.
        {
            const std::string ref = toHex(randomBytes(8));
            alice.sendReaction(bob.fingerprint(), ref, "\xf0\x9f\x91\x8d");
            // The one path that deliberately establishes no dialog.
            alice.sendReceipt(bob.fingerprint(), ref);
            alice.sendDelete(bob.fingerprint(), ref);
            bob.sync();
            CHECK(alice.canWriteTo(bob.fingerprint()));
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
        // Addressed to herself, a message is kept rather than delivered: nothing
        // is presented, nothing is dialled, and it goes to her own mailbox for her
        // other devices to pick up.
        {
            alice.sendMessage(alice.fingerprint(), "note to self");

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
            nlohmann::json saved = {
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
                // Signed as that other device of hers would have signed it: an
                // envelope that cannot name its author is dropped before it is
                // read, which is the whole point of the signature.
                signAuthorship(saved, aliceIdentity, /*withKeys=*/false);
                // The wire carries CBOR, which is what the reader expects.
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice.fingerprint()].push_back({"saved-echo", "device",
                    cms::seal(padToLadder(nlohmann::json::to_cbor(saved)),
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
        // What a block means where the message is read: Bob still holds the pass
        // and still delivers, and none of it reaches her.
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

            // Blocking took the pass out of her mailbox, so his deliveries stop
            // being admitted at all.
            const auto held = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.registered[alice.fingerprint()].size();
            };
            CHECK(held() == 0);

            // Lifting it gives back exactly what it took: the same pass, still in
            // his hands, registered again. Nothing is sent to him, nothing waits
            // for a message to ride on, and he can answer at once - which is the
            // whole of what a block being lifted has to mean.
            alice.setBlocked(bob.fingerprint(), false);
            CHECK(!alice.isBlocked(bob.fingerprint()));
            CHECK(held() == 1);
            CHECK(bob.canWriteTo(alice.fingerprint()));

            // What a client does with a refusal. There is no capability to lose,
            // so no refusal costs anything: the same pass carries the next
            // message whatever the far side said about the last one.
            {
                const auto refuseOnce = [&](const std::string& code) {
                    {
                        std::lock_guard<std::mutex> lock(m.mu);
                        m.refuseWith = code;
                    }
                    try {
                        alice.sendMessage(bob.fingerprint(), "into a refusal");
                    } catch (const std::exception&) {
                        // The send failing is the point; what it did to the pass
                        // is what is being checked.
                    }
                    std::lock_guard<std::mutex> lock(m.mu);
                    m.refuseWith.clear();
                };
                for (const char* code :
                    {"STORAGE_FULL", "RECIPIENT_SERVER_UNREACHABLE", "DELIVERY_REJECTED"}) {
                    refuseOnce(code);
                    alice.sync();
                    CHECK(alice.canWriteTo(bob.fingerprint()));
                }
                alice.sendMessage(bob.fingerprint(), "and this one goes");
            }

            bob.sendMessage(alice.fingerprint(), "after the unblock");
            bool heardAgain = false;
            for (const IncomingMessage& item : alice.sync()) {
                if (item.text == "after the unblock") {
                    heardAgain = true;
                }
            }
            CHECK(heardAgain);
        }

        // A contact who holds our pass can put an envelope in our mailbox - that
        // is what a pass is for - but he cannot put another name on it.
        // Admission is not authorship, and the signature is what tells them
        // apart.
        {
            const Identity bobIdentity
                = Identity::fromPrivatePem(AccountDb(bDir, std::string{}).text("identity.pem"));
            const std::string strangerFingerprint = Identity::generate().fingerprint();
            const auto intoAliceMailbox = [&](const std::string& id, nlohmann::json content) {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice.fingerprint()].push_back({id, "content",
                    cms::seal(padToLadder(nlohmann::json::to_cbor(content)),
                        Key::fromPublicDer(fromBase64(alice.sealingPublicB64())))});
            };
            const auto text = [](const std::string& from, const std::string& id,
                                  const std::string& body) {
                return nlohmann::json{{"v", 1}, {"type", "text"}, {"id", id}, {"from", from},
                    {"sentAt", 1}, {"text", body}};
            };

            // Bob signs, but writes somebody else's name on it.
            nlohmann::json forged = text(strangerFingerprint, "forged-1", "trust me, I am them");
            signAuthorship(forged, bobIdentity, /*withKeys=*/true);
            intoAliceMailbox("forged-1", forged);
            // Bob does not sign at all.
            intoAliceMailbox("unsigned-1", text(bob.fingerprint(), "unsigned-1", "no signature"));
            // And the same message, honestly signed, to prove the gate is not
            // simply dropping everything.
            nlohmann::json honest = text(bob.fingerprint(), "honest-1", "this one is mine");
            signAuthorship(honest, bobIdentity, /*withKeys=*/false);
            intoAliceMailbox("honest-1", honest);

            // And what he cannot do at all: talk on the channel this account
            // uses to talk to itself. A device message is a message from one of
            // her own devices; his signature proves he is not one, whatever the
            // type says. Two of them are worth the check by themselves - one
            // changes a setting of hers, the other writes into her address book.
            const std::string plantedPeer = Identity::generate().fingerprint();
            const auto deviceNotice = [&](const std::string& id, nlohmann::json extra) {
                extra["v"] = 1;
                extra["id"] = id;
                extra["from"] = bob.fingerprint();
                extra["sentAt"] = 1;
                extra["device"] = "not-a-device-of-hers";
                signAuthorship(extra, bobIdentity, /*withKeys=*/false);
                intoAliceMailbox(id, extra);
            };
            const std::int64_t termBefore = alice.delegationDays();
            deviceNotice("bob-term", {{"type", "device.delegation-term"},
                                         {"days", termBefore == 7 ? 30 : 7}});
            deviceNotice("bob-book",
                {{"type", "device.contacts"},
                    {"forDevice", "not-a-device-of-hers"},
                    {"contacts", nlohmann::json::array({nlohmann::json{
                                     {"fingerprint", plantedPeer},
                                     {"dest", "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p"},
                                     {"displayName", "planted"}}})}});

            bool sawForged = false;
            bool sawUnsigned = false;
            bool sawHonest = false;
            for (const IncomingMessage& item : alice.sync()) {
                sawForged = sawForged || item.text == "trust me, I am them";
                sawUnsigned = sawUnsigned || item.text == "no signature";
                sawHonest = sawHonest || item.text == "this one is mine";
            }
            CHECK(!sawForged);
            // Neither notice was his to send.
            CHECK(alice.delegationDays() == termBefore);
            CHECK(!alice.hasContact(plantedPeer));
            CHECK(!sawUnsigned);
            CHECK(sawHonest);
        }

        // The one thing a stranger may put in a mailbox is a contact request, so
        // its size has to be a known number rather than a generous one: the cap
        // is what the worst case actually weighs. Build that worst case - the
        // longest name this account may carry and the longest greeting a user may
        // write - and measure it where the server sees it.
        {
            const fs::path cDir = fs::temp_directory_path() / "bz-pass-c";
            fs::remove(cDir);
            Session carol = Session::create(cDir, endpoint, std::string{});
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[carol.fingerprint()]
                    = "flkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            }
            carol.registerAccount();
            carol.setFetchTransport(directDial);
            carol.setOutboundCourier(courierFor());

            const std::string longestName(kMaxAccountNameBytes, 'n');
            alice.setDisplayName(longestName);
            CHECK(alice.displayName() == longestName);
            const std::string longestGreeting(kMaxContactGreetingBytes, 'g');
            alice.addByInvite(carol.inviteUri(), longestGreeting);

            const std::size_t largest = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.largestContactRequest;
            }();
            std::printf("TestDeliveryPass: the largest contact request is %zu bytes\n", largest);
            CHECK(largest <= kMaxContactRequestBytes);
            // And no slack: room above the worst case is room for a stranger to
            // fill a mailbox with. A drift either way has to be noticed here.
            CHECK(kMaxContactRequestBytes - largest < 64);
        }

        // --- A request buys nothing until it is agreed to ---
        //
        // Two requests from one stranger used to be exactly what it took to make
        // this side answer: each carries an unaddressed reply batch, a device that
        // is one of several takes one token out of each, and the errand that buys a
        // batch of its own fires at two. That errand carried the bootstrap, so it
        // was an acceptance nobody gave - and the Agree button went with it.
        {
            const fs::path dDir = fs::temp_directory_path() / "bz-pass-d";
            fs::remove(dDir);
            Session dana = Session::create(dDir, endpoint, std::string{});
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[dana.fingerprint()]
                    = "glkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            }
            dana.registerAccount();
            dana.setFetchTransport(directDial);
            dana.setOutboundCourier(courierFor());

            const auto heldForAlice = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice.fingerprint()].size();
            };
            const std::size_t beforeRequests = heldForAlice();
            // Asked twice, the way a resend asks: two requests, two batches.
            alice.addByInvite(dana.inviteUri(), "let me in");
            alice.addByInvite(dana.inviteUri(), "let me in again");
            for (int round = 0; round < 3; ++round) {
                dana.sync();
            }
            CHECK(dana.hasContact(alice.fingerprint()));
            // Unanswered, so the button is still there to press...
            CHECK(dana.contactIsPending(alice.fingerprint()));
            // ...and nothing at all has gone back to her.
            CHECK(heldForAlice() == beforeRequests);

            // Reading the request is not answering it: no receipt goes back, so a
            // requester learns nothing about a stranger's client from having
            // asked.
            dana.sendReceipt(alice.fingerprint(), "whatever-they-sent");
            CHECK(heldForAlice() == beforeRequests);

            // Agreeing is what opens the way back - once the batch it carries is
            // in her mailbox, and not on the strength of a send that left here.
            dana.acceptContactRequest(alice.fingerprint());
            CHECK(dana.contactIsPending(alice.fingerprint()));
            CHECK(dana.contactAcceptInFlight(alice.fingerprint()));
            // A second Agree while the first is in the air mints no second batch.
            dana.acceptContactRequest(alice.fingerprint());
            CHECK(waitFor([&]() { return heldForAlice() > beforeRequests; }));
            for (int round = 0; round < 3 && dana.contactIsPending(alice.fingerprint());
                ++round) {
                dana.sync();  // where a confirmed acceptance is written down
            }
            CHECK(!dana.contactIsPending(alice.fingerprint()));
            CHECK(!dana.contactAcceptInFlight(alice.fingerprint()));
        }

        // --- A second device of this account asks for the address book ---
        //
        // The one thing a fresh device cannot get from the network: no lookup
        // turns a fingerprint into a destination, and the capability to read a
        // card is held by the devices that already have the contact. So it asks,
        // and the device that has the book answers over the account's own
        // mailbox.
        {
            // Bob's face reaches Alice the ordinary way, so the book has one to
            // carry.
            const Bytes face = {0xFF, 0xD8, 0xFF, 0xE0, 'b', 'o', 'b'};
            bob.setAvatar(face, "image/jpeg");
            for (int round = 0; round < 3 && alice.contactAvatar(bob.fingerprint()).empty();
                ++round) {
                alice.sync();
            }
            CHECK(alice.contactAvatar(bob.fingerprint()) == face);
            alice.renameContact(bob.fingerprint(), "Bob of the book");

            const fs::path secondDir = fs::temp_directory_path() / "bz-pass-a-second.db";
            fs::remove(secondDir);
            Session::importAccount(earlyBundle, secondDir, "bundle-password");
            Session second = Session::open(secondDir, std::string{});
            // A device id is drawn fresh on import, which is what makes the two
            // devices distinguishable at all.
            CHECK(second.fingerprint() == alice.fingerprint());
            CHECK(!second.hasContact(bob.fingerprint()));

            // First sync: the question goes out (once per device, automatically).
            second.sync();
            // Alice answers it.
            alice.sync();
            // And the book arrives.
            for (int round = 0; round < 3 && !second.hasContact(bob.fingerprint()); ++round) {
                second.sync();
            }
            CHECK(second.hasContact(bob.fingerprint()));
            CHECK(second.contactDisplayName(bob.fingerprint()) == "Bob of the book");
            CHECK(second.contactAvatar(bob.fingerprint()) == face);
            // The pass travels with the book, so a device that has just learned a
            // contact can write to them at once. This is the inversion: what was
            // deliberately withheld - a one-time capability cannot be in two
            // places - is now the thing that must be carried.
            CHECK(second.canWriteTo(bob.fingerprint()));
            // What arrived is enough to check what Bob writes: his keys came with
            // the book, so the second device can read him without them on the
            // wire. A message he sends now is verified against exactly those.
            bob.sendMessage(alice.fingerprint(), "hello, second device");
            bool sawBob = false;
            for (int round = 0; round < 3 && !sawBob; ++round) {
                for (const IncomingMessage& item : second.sync()) {
                    sawBob = sawBob || item.text == "hello, second device";
                }
            }
            CHECK(sawBob);

            // An avatar too big for one message is left behind rather than
            // splitting the contact across two: the face arrives again from the
            // correspondent, the address it is reached at cannot.
            {
                const Bytes huge(200 * 1024, 0x41);
                bob.setAvatar(huge, "image/jpeg");
                for (int round = 0; round < 3 && alice.contactAvatar(bob.fingerprint()) != huge;
                    ++round) {
                    alice.sync();
                }
                CHECK(alice.contactAvatar(bob.fingerprint()) == huge);

                const fs::path thirdDir = fs::temp_directory_path() / "bz-pass-a-third.db";
                fs::remove(thirdDir);
                Session::importAccount(earlyBundle, thirdDir, "bundle-password");
                Session third = Session::open(thirdDir, std::string{});
                third.sync();
                alice.sync();
                for (int round = 0; round < 3 && !third.hasContact(bob.fingerprint()); ++round) {
                    third.sync();
                }
                CHECK(third.hasContact(bob.fingerprint()));
                CHECK(third.contactAvatar(bob.fingerprint()).empty());
                CHECK(third.contactDisplayName(bob.fingerprint()) == "Bob of the book");
            }

            // Asked once: a second sync does not ask again.
            const std::size_t before = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice.fingerprint()].size();
            }();
            second.sync();
            const std::size_t after = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice.fingerprint()].size();
            }();
            // Nothing new is written by that sync: the question is asked once
            // per device. Items may still be consumed by it - this device's own
            // token asks are addressed to the account, so it fetches them too.
            CHECK(after <= before);
            // And Alice does not answer a question that was not asked again: the
            // book stays one contact, not two copies of one.
            alice.sync();
            second.sync();
            CHECK(second.hasContact(bob.fingerprint()));
            CHECK(second.contactDisplayName(bob.fingerprint()) == "Bob of the book");

            // A backup taken with contacts in place copies each conversation's
            // pass rather than handing it over: the exporting device keeps
            // writing and the restored one can write from its first sync.
            CHECK(alice.canWriteTo(bob.fingerprint()));
            const fs::path laterBundle = fs::temp_directory_path() / "bz-pass-later.bundle";
            fs::remove(laterBundle);
            alice.exportAccount(laterBundle, "bundle-password");
            CHECK(alice.canWriteTo(bob.fingerprint()));

            const fs::path fourthDir = fs::temp_directory_path() / "bz-pass-a-fourth.db";
            fs::remove(fourthDir);
            Session::importAccount(laterBundle, fourthDir, "bundle-password");
            Session fourth = Session::open(fourthDir, std::string{});
            CHECK(fourth.hasContact(bob.fingerprint()));
            CHECK(fourth.canWriteTo(bob.fingerprint()));
            fourth.sync();
            CHECK(fourth.canWriteTo(bob.fingerprint()));
        }

        // --- What another device of ours says, and what this one does with it ---
        //
        // Each notice is built as the wire carries it, under another device id,
        // and handed to her: what matters is that it is applied here.
        {
            const auto fromAnotherDevice = [&](nlohmann::json notice) {
                // Signed with this account's key, which is what a device of hers
                // holds: unsigned, it would be dropped before it is read.
                signAuthorship(notice, aliceIdentity, /*withKeys=*/false);
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice.fingerprint()].push_back({"self-" + notice.at("id").get<std::string>(),
                    "device",
                    cms::seal(padToLadder(nlohmann::json::to_cbor(notice)),
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
                    cms::seal(padToLadder(nlohmann::json::to_cbor(inner)),
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

    std::fprintf(stderr, "TestDeliveryPass passed (bob sent %d, alice sent %d)\n", bobSent, aliceSent);
    return 0;
}
