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

#include "TestUtil.hpp"

#include <functional>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace {

namespace fs = std::filesystem;

std::string requireCaller(const http::Request& request)
{
    const std::string caller = request.header(bazarish::teststub::kCallerHeader);
    if (caller.empty()) {
        throw std::runtime_error("no caller: this request did not come through the tunnel");
    }
    return caller;
}

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
    options.port = 0;
    options.threads = 16;
    return options;
}

void respondJson(http::Response& response, const nlohmann::json& body)
{
    response.contentType = "application/json";
    response.body = body.dump();
}

constexpr const char* kTestResolverDest
    = "flkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";

struct Mock {
    std::mutex mu;
    std::string serverFp;
    Key serverSealing = Key::generateSealing();
    std::map<std::string, std::string> destFor;
    std::map<std::string, std::string> certFor;  // fingerprint -> contact card (base64 DER)
    std::map<std::string, std::string> viewFor;
    std::set<std::string> delegated;
    struct Item {
        std::string id;
        std::string cls;
        Bytes payload;
    };
    std::map<std::string, std::vector<Item>> mailbox;
    std::map<std::string, std::set<std::string>> registered;
    std::map<std::string, std::set<std::string>> seenIds;
    std::size_t largestContactRequest = 0;
    int nextId = 1;
    std::string refuseWith;
    std::map<std::string, std::string> pendingView;
    std::map<std::string, std::string> aliasOwner;
    std::map<std::string, Descriptor> aliasDescriptor;
    std::set<std::string> aliasBindingWanted;
    int resolverStatusCalls = 0;
    int resolverUpdateCalls = 0;
};

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
                const nlohmann::json refusal = {{"delivered", false},
                    {"errorCode", mock_.refuseWith}, {"errorMessage", "refused by the test"}};
                return refusal.dump() + "\n";
            }
            const bool fresh = mock_.seenIds[mailbox].count(deliveryId) == 0;
            if (cls == "content" && fresh) {
                const Bytes presented = fromBase64(inner.at("pass").get<std::string>());
                if (mock_.registered[mailbox].count(toBase64(deliveryPassHandle(presented)))
                    != 1) {
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
            const bool delegated = m.delegated.count(caller) > 0;
            respondJson(response,
                {{"dest", delegated ? m.destFor[caller] : std::string()},
                    {"servingKey", toBase64(m.serverSealing.publicDer())}});
        }));

    const auto handlePublishCard
        = [&](const http::Request& request, http::Response& response) {
              const std::string caller = requireCaller(request);
              const std::string cardB64
                  = nlohmann::json::parse(request.body).at("card").get<std::string>();
              const ContactCard card = ContactCard::verify(fromBase64(cardB64));
              CHECK(card.fingerprint() == caller);
              {
                  std::lock_guard<std::mutex> lock(m.mu);
                  const auto held = m.certFor.find(caller);
                  if (held != m.certFor.end() && !held->second.empty()) {
                      const ContactCard previous = ContactCard::verify(fromBase64(held->second));
                      if (card.issuedAt <= previous.issuedAt) {
                          response.status = 409;
                          respondJson(response,
                              {{"error",
                                  {{"code", "DELIVERY_REJECTED"},
                                      {"message",
                                          "this card is not newer than the one already "
                                          "published"}}}});
                          return;
                      }
                  }
                  m.certFor[caller] = cardB64;
              }
              const std::string view = toHex(sha256(Bytes(caller.begin(), caller.end())))
                                           .substr(0, bazarish::kViewCapabilityChars);
              {
                  std::lock_guard<std::mutex> lock(m.mu);
                  m.viewFor[caller] = view;
              }
              respondJson(response, {{"quotaBytes", 100u * 1024 * 1024}, {"view", view}});
          };
    server.post("/v1/account/card", stub(handlePublishCard));

    server.post("/v1/account/serving-key",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
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

    server.post("/v1/account/i2p-dest",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            CHECK(!nlohmann::json::parse(request.body).at("transient").get<std::string>().empty());
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.delegated.insert(caller);
            }
            respondJson(response, {{"ok", true}});
        }));

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

    const Identity stubServerIdentity = Identity::generate();
    const Key stubServerSealing = Key::generateSealing();
    bazarish::teststub::Tunnel tunnelStub(server, stubServerIdentity, stubServerSealing);
    const int port = server.start();
    CHECK(port > 0);

    ServerEndpoint endpoint;
    endpoint.serverFingerprint = stubServerIdentity.fingerprint();
    endpoint.facades = {Facade{false, "127.0.0.1", port, {}}};

    const Identity resolverRoot = Identity::generate();
    const Identity resolverDelegated = Identity::generate();
    const Bytes resolverDelegationDer = DelegationCertificate::issue(resolverRoot,
        resolverDelegated, static_cast<std::int64_t>(std::time(nullptr)) - 60,
        static_cast<std::int64_t>(std::time(nullptr)) + 30 * 24 * 3600);

    const fs::path aDir = fs::temp_directory_path() / "bz-pass-a";
    const fs::path bDir = fs::temp_directory_path() / "bz-pass-b";
    fs::remove_all(aDir);
    fs::remove_all(bDir);

    int bobSent = 0;
    int aliceSent = 0;

    {
        Session alice = Session::create(aDir, endpoint, std::string{});
        Session bob = Session::create(bDir, endpoint, std::string{});
        const ResolverCoordinate resolver{resolverRoot.fingerprint(), kTestResolverDest};
        alice.setResolverCoordinate(resolver);
        bob.setResolverCoordinate(resolver);
        const Identity aliceIdentity
            = Identity::fromPrivatePem(AccountDb(aDir, std::string{}).text("identity.pem"));
        const fs::path earlyBundle = fs::temp_directory_path() / "bz-pass-early.bundle";
        fs::remove(earlyBundle);
        alice.exportAccount(earlyBundle, "bundle-password");
        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.destFor[alice.fingerprint()] = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            m.destFor[bob.fingerprint()] = "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
        }

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

        CHECK(!alice.inviteUri().empty());
        CHECK(alice.inviteUri().find(m.destFor[alice.fingerprint()]) != std::string::npos);
        CHECK(!bob.inviteUri().empty());

        const auto directDial = [&m, &resolverRoot, &resolverDelegated, &resolverDelegationDer](
                                    const std::string& toDest, const std::string& op,
                                    const Bytes& query) {
            if (op == kAliasStatusOp || op == kAliasUpdateOp) {
                CHECK(toDest == kTestResolverDest);
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
                    if (m.aliasBindingWanted.count(asked.request.alias) == 0) {
                        outcome.errorCode = "NOT_OWNER";
                        return outcome;
                    }
                    CHECK(asked.request.descriptor.fingerprint == asked.owner);
                    CHECK(!asked.request.aliasCertDer.empty());
                    const AliasCertificate claim
                        = AliasCertificate::verify(asked.request.aliasCertDer);
                    CHECK(claim.user == asked.owner);
                    CHECK(claim.alias == asked.request.alias);
                    m.aliasDescriptor[asked.request.alias] = asked.request.descriptor;
                    outcome.ok = true;
                    return outcome;
                }
                ++m.resolverStatusCalls;
                AliasStatus status;
                status.owner = asked.owner;
                for (const auto& [alias, owner] : m.aliasOwner) {
                    if (owner != asked.owner) {
                        continue;
                    }
                    AliasStatusEntry one;
                    one.alias = alias;
                    one.notAfter = now + 365 * 24 * 3600;
                    one.bindingWanted = m.aliasBindingWanted.count(alias) != 0;
                    one.bound = m.aliasDescriptor.count(alias) != 0;
                    status.names.push_back(std::move(one));
                }
                status.issuedAt = now;
                status.notAfter = now + kAliasStatusValiditySeconds;
                const ResolveResponse answer{
                    signAliasStatus(status, resolverDelegated), resolverDelegationDer, Bytes{}};
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

        alice.addByInvite(bob.inviteUri(), "hi bob");
        bob.sync();
        bob.acceptContactRequest(alice.fingerprint());
        alice.sync();
        CHECK(alice.hasContact(bob.fingerprint()));
        CHECK(bob.hasContact(alice.fingerprint()));

        CHECK(waitFor([&]() {
            alice.sync();
            return alice.canWriteTo(bob.fingerprint());
        }));

        CHECK(alice.aliasNames().empty());
        alice.serviceAliases();
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.resolverStatusCalls == 0);
            CHECK(m.resolverUpdateCalls == 0);
        }

        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasOwner["alice"] = alice.fingerprint();
        }
        CHECK(alice.refreshAliasStatus());
        CHECK(alice.aliasNames().size() == 1);
        CHECK(alice.aliasNames().front().alias == "alice");

        CHECK(!alice.aliasNames().front().bindingWanted);
        CHECK(!alice.aliasUpdatePending());
        const int updatesBeforeAsking = m.resolverUpdateCalls;
        alice.serviceAliases();
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.resolverUpdateCalls == updatesBeforeAsking);
            CHECK(m.aliasDescriptor.count("alice") == 0);
        }

        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasBindingWanted.insert("alice");
        }
        CHECK(alice.refreshAliasStatus());
        CHECK(alice.aliasNames().front().bindingWanted);
        CHECK(alice.aliasUpdatePending());
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.count("alice") == 0);
        }
        CHECK(alice.pushAliasDescriptor());
        CHECK(!alice.aliasUpdatePending());
        const int updatesBeforePressingAgain = m.resolverUpdateCalls;
        CHECK(!alice.pushAliasDescriptor());
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.resolverUpdateCalls == updatesBeforePressingAgain);
            CHECK(m.aliasDescriptor.at("alice").fingerprint == alice.fingerprint());
            CHECK(m.aliasDescriptor.at("alice").view == m.viewFor[alice.fingerprint()]);
        }

        const std::string viewBefore = m.viewFor[alice.fingerprint()];
        alice.rotateServingKey(nullptr);
        const std::string viewAfter = m.viewFor[alice.fingerprint()];
        CHECK(viewAfter != viewBefore);
        CHECK(!alice.aliasUpdatePending());
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.at("alice").view == viewAfter);
        }

        {
            const std::lock_guard<std::mutex> lock(m.mu);
            m.aliasBindingWanted.erase("alice");
            m.aliasDescriptor.erase("alice");
        }
        CHECK(alice.refreshAliasStatus());
        CHECK(!alice.aliasNames().front().bindingWanted);
        CHECK(!alice.aliasUpdatePending());
        {
            const std::lock_guard<std::mutex> lock(m.mu);
            m.aliasBindingWanted.insert("alice");
        }
        CHECK(alice.refreshAliasStatus());
        CHECK(alice.aliasNames().front().bindingWanted);
        CHECK(!alice.aliasNames().front().bound);
        CHECK(alice.aliasUpdatePending());
        CHECK(alice.pushAliasDescriptor());
        CHECK(!alice.aliasUpdatePending());
        {
            const std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.at("alice").fingerprint == alice.fingerprint());
        }

        // A name somebody else owns is not repointed by asking nicely.
        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasOwner["bob"] = bob.fingerprint();
        }
        CHECK(bob.aliasNames().empty());
        const int statusBefore = m.resolverStatusCalls;
        bob.rotateServingKey(nullptr);
        CHECK(m.resolverStatusCalls == statusBefore + 1);
        CHECK(bob.aliasNames().size() == 1);
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.count("bob") == 0);
            CHECK(m.aliasDescriptor.at("alice").fingerprint == alice.fingerprint());
        }

        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasBindingWanted.insert("bob");
        }
        const int bobStatusBefore = m.resolverStatusCalls;
        const Session::AliasErrandResult errand
            = Session::runAliasErrand(bob.aliasErrandContext());
        CHECK(errand.ok);
        CHECK(errand.haveStatus);
        CHECK(errand.pointed);
        CHECK(m.resolverStatusCalls == bobStatusBefore + 1);
        bob.applyAliasErrand(errand);
        CHECK(bob.aliasNames().size() == 1);
        CHECK(!bob.aliasUpdatePending());
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.at("bob").fingerprint == bob.fingerprint());
        }
        CHECK(bob.canWriteTo(alice.fingerprint()));
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.registered[alice.fingerprint()].size() == 1);
            CHECK(m.registered[bob.fingerprint()].size() == 1);
        }

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
            CHECK(logHas(aliceLog, "POST /v1/messaging/", "200"));
            for (const WireEvent& event : aliceLog) {
                CHECK(event.what.find("logged") == std::string::npos);
                CHECK(event.detail.find("logged") == std::string::npos);
            }
            bob.sync();
            CHECK(logHas(bob.connectionLog(), "text from", {}));
            alice.setDisplayName("Alice of the log");
            CHECK(logHas(alice.connectionLog(),
                "POST /v1/messaging/self (device.account-name)", "200"));
        }

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

        {
            CHECK(alice.pushRoutingToContacts({}).told > 0);
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

        {
            const std::string ref = toHex(randomBytes(8));
            alice.sendReaction(bob.fingerprint(), ref, "\xf0\x9f\x91\x8d");
            alice.sendReceipt(bob.fingerprint(), ref);
            alice.sendDelete(bob.fingerprint(), ref);
            bob.sync();
            CHECK(alice.canWriteTo(bob.fingerprint()));
        }

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

        {
            alice.sendMessage(alice.fingerprint(), "note to self");

            std::size_t deviceItems = 0;
            {
                std::lock_guard<std::mutex> lock(m.mu);
                for (const Mock::Item& item : m.mailbox[alice.fingerprint()]) {
                    deviceItems += item.cls == "device" ? 1 : 0;
                }
            }
            CHECK(deviceItems >= 1);

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
                signAuthorship(saved, aliceIdentity, /*withKeys=*/false);
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

            bool refused = false;
            try {
                alice.sendFile(alice.fingerprint(), aDir / "meta", "", {}, "");
            } catch (const std::exception&) {
                refused = true;
            }
            CHECK(refused);
        }

        {
            alice.renameContact(bob.fingerprint(), "Saved messages");
            CHECK(alice.contactDisplayName(bob.fingerprint()) == "(Contact) Saved messages");
            alice.renameContact(bob.fingerprint(), "  saved MESSAGES  ");
            CHECK(alice.contactDisplayName(bob.fingerprint()) == "(Contact)   saved MESSAGES  ");
            alice.renameContact(bob.fingerprint(), "Bob");
            CHECK(alice.contactDisplayName(bob.fingerprint()) == "Bob");
        }

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
            {
                std::lock_guard<std::mutex> lock(m.mu);
                CHECK(m.mailbox[alice.fingerprint()].empty());
            }

            bool sendRefused = false;
            try {
                alice.sendMessage(bob.fingerprint(), "still there?");
            } catch (const std::exception&) {
                sendRefused = true;
            }
            CHECK(sendRefused);

            const auto held = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.registered[alice.fingerprint()].size();
            };
            CHECK(held() == 0);

            alice.setBlocked(bob.fingerprint(), false);
            CHECK(!alice.isBlocked(bob.fingerprint()));
            CHECK(held() == 1);
            CHECK(bob.canWriteTo(alice.fingerprint()));

            {
                const auto refuseOnce = [&](const std::string& code) {
                    {
                        std::lock_guard<std::mutex> lock(m.mu);
                        m.refuseWith = code;
                    }
                    try {
                        alice.sendMessage(bob.fingerprint(), "into a refusal");
                    } catch (const std::exception&) {
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

            nlohmann::json forged = text(strangerFingerprint, "forged-1", "trust me, I am them");
            signAuthorship(forged, bobIdentity, /*withKeys=*/true);
            intoAliceMailbox("forged-1", forged);
            intoAliceMailbox("unsigned-1", text(bob.fingerprint(), "unsigned-1", "no signature"));
            nlohmann::json honest = text(bob.fingerprint(), "honest-1", "this one is mine");
            signAuthorship(honest, bobIdentity, /*withKeys=*/false);
            intoAliceMailbox("honest-1", honest);

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
            CHECK(alice.delegationDays() == termBefore);
            CHECK(!alice.hasContact(plantedPeer));
            CHECK(!sawUnsigned);
            CHECK(sawHonest);
        }

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
            CHECK(kMaxContactRequestBytes - largest < 64);
        }

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
            alice.addByInvite(dana.inviteUri(), "let me in");
            bool askedTwice = true;
            try {
                alice.addByInvite(dana.inviteUri(), "let me in again");
            } catch (const std::exception&) {
                askedTwice = false;
            }
            CHECK(!askedTwice);
            CHECK(alice.hasContact(dana.fingerprint()));
            for (int round = 0; round < 3; ++round) {
                dana.sync();
            }
            CHECK(dana.hasContact(alice.fingerprint()));
            CHECK(dana.contactIsPending(alice.fingerprint()));
            CHECK(heldForAlice() == beforeRequests);

            dana.sendReceipt(alice.fingerprint(), "whatever-they-sent");
            CHECK(heldForAlice() == beforeRequests);

            dana.acceptContactRequest(alice.fingerprint());
            CHECK(dana.contactIsPending(alice.fingerprint()));
            CHECK(dana.contactAcceptInFlight(alice.fingerprint()));
            dana.acceptContactRequest(alice.fingerprint());
            CHECK(waitFor([&]() { return heldForAlice() > beforeRequests; }));
            for (int round = 0; round < 3 && dana.contactIsPending(alice.fingerprint());
                ++round) {
                dana.sync();
            }
            CHECK(!dana.contactIsPending(alice.fingerprint()));
            CHECK(!dana.contactAcceptInFlight(alice.fingerprint()));

            alice.removeContact(dana.fingerprint());
            CHECK(!alice.hasContact(dana.fingerprint()));
            const std::size_t beforeReturn = heldForAlice();
            alice.addByInvite(dana.inviteUri(), "me again");
            for (int round = 0; round < 3 && !dana.contactAcceptInFlight(alice.fingerprint());
                ++round) {
                dana.sync();
            }
            CHECK(waitFor([&]() { return heldForAlice() > beforeReturn; }));
            for (int round = 0; round < 3 && dana.contactIsPending(alice.fingerprint());
                ++round) {
                dana.sync();
            }
            CHECK(!dana.contactIsPending(alice.fingerprint()));
            CHECK(waitFor([&]() {
                alice.sync();
                return alice.canWriteTo(dana.fingerprint());
            }));
        }

        {
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
            CHECK(second.fingerprint() == alice.fingerprint());
            CHECK(!second.hasContact(bob.fingerprint()));

            second.sync();
            alice.sync();
            for (int round = 0; round < 3 && !second.hasContact(bob.fingerprint()); ++round) {
                second.sync();
            }
            CHECK(second.hasContact(bob.fingerprint()));
            CHECK(second.contactDisplayName(bob.fingerprint()) == "Bob of the book");
            CHECK(second.contactAvatar(bob.fingerprint()) == face);
            CHECK(second.canWriteTo(bob.fingerprint()));
            bob.sendMessage(alice.fingerprint(), "hello, second device");
            bool sawBob = false;
            for (int round = 0; round < 3 && !sawBob; ++round) {
                for (const IncomingMessage& item : second.sync()) {
                    sawBob = sawBob || item.text == "hello, second device";
                }
            }
            CHECK(sawBob);

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

            const std::size_t before = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice.fingerprint()].size();
            }();
            second.sync();
            const std::size_t after = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice.fingerprint()].size();
            }();
            CHECK(after <= before);
            alice.sync();
            second.sync();
            CHECK(second.hasContact(bob.fingerprint()));
            CHECK(second.contactDisplayName(bob.fingerprint()) == "Bob of the book");

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

        {
            const auto fromAnotherDevice = [&](nlohmann::json notice) {
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

            CHECK(alice.displayName() != "renamed elsewhere");
            fromAnotherDevice(notice("device.account-name", {{"name", "renamed elsewhere"}}));
            alice.sync();
            CHECK(alice.displayName() == "renamed elsewhere");

            CHECK(alice.acceptCalls());
            CHECK(alice.sendReceipts());
            fromAnotherDevice(notice("device.account-prefs",
                {{"acceptCalls", false}, {"sendReceipts", false}}));
            alice.sync();
            CHECK(!alice.acceptCalls());
            CHECK(!alice.sendReceipts());
            fromAnotherDevice(notice("device.account-prefs", {{"acceptCalls", true}}));
            alice.sync();
            CHECK(alice.acceptCalls());
            CHECK(!alice.sendReceipts());
            alice.setSendReceipts(true);

            fromAnotherDevice(notice("device.contact-prefs",
                {{"peer", bob.fingerprint()}, {"notifications", false}, {"allowCalls", false}}));
            alice.sync();
            CHECK(!alice.contactNotifications(bob.fingerprint()));
            CHECK(!alice.contactCalls(bob.fingerprint()));

            const std::string stranger = std::string(52, 'y');
            fromAnotherDevice(notice("device.contact-block",
                {{"peer", stranger}, {"blocked", true}}));
            alice.sync();
            CHECK(alice.isBlocked(stranger));
            fromAnotherDevice(notice("device.contact-block",
                {{"peer", stranger}, {"blocked", false}}));
            alice.sync();
            CHECK(!alice.isBlocked(stranger));

            fromAnotherDevice(notice("device.chat-clear", {{"peer", bob.fingerprint()}}));
            bool sawClear = false;
            for (const IncomingMessage& item : alice.sync()) {
                if (item.contentType == "device.chat-clear") {
                    sawClear = true;
                    CHECK(item.refId == bob.fingerprint());
                }
            }
            CHECK(sawClear);

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
