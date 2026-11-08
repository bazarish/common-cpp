// Bazarish project (c) 2026
#include "GatewayAddress.hpp"
#include "I2pKeys.hpp"
#include "I2pRouter.hpp"
#include "Client.hpp"
#include "OutboundCourier.hpp"
#include "AccountDb.hpp"
#include "Authorship.hpp"
#include "Session.hpp"
#include "WireLog.hpp"

#include "FakeGateway.hpp"
#include "TunnelStub.hpp"

#include <bazarish/AliasMaintenance.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/Padding.hpp>
#include <bazarish/Pass.hpp>

#include <bazarish/HttpServer.hpp>

#include "TestUtil.hpp"

#include <functional>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <array>
#include <iterator>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
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

constexpr int kServiceUnavailable = 503;
constexpr std::size_t kSneakPassBytes = 32;
constexpr std::array<std::uint8_t, 3> kJpegOpening{0xFF, 0xD8, 0xFF};

void respondJson(http::Response& response, const nlohmann::json& body)
{
    response.contentType = "application/json";
    response.body = body.dump();
}

constexpr const char* kTestResolverDest
    = "flkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";

struct Mock {
    std::mutex mu;
    std::map<std::string, std::string> sealingFor;
    std::map<std::string, std::string> destFor;
    std::map<std::string, std::string> certFor;  // fingerprint -> contact card (base64 DER)
    std::set<std::string> delegated;
    struct Item {
        std::string id;
        std::string cls;
        Bytes payload;
    };
    std::map<std::string, std::vector<Item>> mailbox;
    std::map<std::string, std::size_t> fetches;
    std::map<std::string, std::size_t> acks;
    std::map<std::string, std::set<std::string>> registered;
    std::map<std::string, std::set<std::string>> seenIds;
    std::size_t largestContactRequest = 0;
    int nextId = 1;
    std::string refuseWith;
    int failAcks = 0;
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
    // Only the server operating the recipient's address holds the key that opens its envelopes.
    Bytes openedHere(const Bytes& sealed) const
    {
        std::map<std::string, std::string> keys;
        {
            std::lock_guard<std::mutex> lock(mock_.mu);
            keys = mock_.sealingFor;
        }
        for (const auto& [fingerprint, pem] : keys) {
            try {
                return hybrid::unseal(sealed, Key::fromPrivatePem(pem));
            } catch (const std::exception&) {
                continue;
            }
        }
        throw std::runtime_error("no address served here opens this envelope");
    }

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
        const nlohmann::json inner = nlohmann::json::parse(openedHere(sealed));
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
    http::Server gatewayServer(http::Server::Options{});
    test::FakeGateway gateway;
    const int gatewayPort = gateway.start(gatewayServer);
    CHECK(gatewayPort > 0);
    const std::optional<GatewayAddress> gatewayAt
        = GatewayAddress::parse("http://127.0.0.1:" + std::to_string(gatewayPort)
            + test::kFakeGatewayPath + "#" + gateway.fingerprint());
    CHECK(gatewayAt.has_value());
    CHECK(applyI2pTransport([&gatewayAt]() { setGatewayTransport(*gatewayAt); }));
    Mock m;

    http::Server server(localOptions());

    server.get("/v1/messaging/destination",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            std::lock_guard<std::mutex> lock(m.mu);
            const bool delegated = m.delegated.count(caller) > 0;
            respondJson(response, {{"dest", delegated ? m.destFor[caller] : std::string()}});
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
                                  {{"code", "REQUEST_FAILED"},
                                      {"message",
                                          "this card is not newer than the one already "
                                          "published"}}}});
                          return;
                      }
                  }
                  m.certFor[caller] = cardB64;
              }
              respondJson(response, {{"quotaBytes", 100u * 1024 * 1024}, {"approval", "approved"},
                  {"registrationMessage", ""}});
          };
    server.post("/v1/account/card", stub(handlePublishCard));

    server.post("/v1/account/i2p-dest",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const nlohmann::json body = nlohmann::json::parse(request.body);
            CHECK(!body.at("transient").get<std::string>().empty());
            const std::string sealingPem = body.at("sealingKey").get<std::string>();
            CHECK(Key::fromPrivatePem(sealingPem).hasKem());
            CHECK(Key::fromPrivatePem(body.at("signingKey").get<std::string>()).isA("ED25519"));
            const std::string address
                = i2pRoutingHost(fromBase64(body.at("transient").get<std::string>()));
            std::lock_guard<std::mutex> lock(m.mu);
            m.delegated.insert(caller);
            m.sealingFor[caller] = sealingPem;
            m.destFor[caller] = address;
            respondJson(response, {{"dest", address}});
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
                pending.push_back(
                    {{"id", item.id}, {"class", item.cls}, {"bytes", item.payload.size()}});
            }
            respondJson(response, {{"pending", pending}});
        }));

    server.post("/v1/messaging/fetch",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const nlohmann::json ids = nlohmann::json::parse(request.body).at("ids");
            std::lock_guard<std::mutex> lock(m.mu);
            nlohmann::json items = nlohmann::json::array();
            for (const nlohmann::json& id : ids) {
                for (const Mock::Item& item : m.mailbox[caller]) {
                    if (item.id == id.get<std::string>()) {
                        items.push_back({{"id", item.id},
                            {"blob", nlohmann::json::binary(std::vector<std::uint8_t>(
                                         item.payload.begin(), item.payload.end()))}});
                    }
                }
            }
            ++m.fetches[caller];
            const std::vector<std::uint8_t> answer = nlohmann::json::to_cbor({{"items", items}});
            response.contentType = "application/cbor";
            response.body = std::string(answer.begin(), answer.end());
        }));

    server.post("/v1/messaging/ack",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const nlohmann::json ids = nlohmann::json::parse(request.body).at("ids");
            std::lock_guard<std::mutex> lock(m.mu);
            if (m.failAcks > 0) {
                --m.failAcks;
                response.status = kServiceUnavailable;
                respondJson(response,
                    {{"errorCode", "INTERNAL"}, {"errorMessage", "ack refused by the test"}});
                return;
            }
            std::vector<Mock::Item>& box = m.mailbox[caller];
            for (const nlohmann::json& id : ids) {
                const std::string acked = id.get<std::string>();
                box.erase(std::remove_if(box.begin(), box.end(),
                              [&](const Mock::Item& item) { return item.id == acked; }),
                    box.end());
            }
            ++m.acks[caller];
            respondJson(response, {{"ok", true}});
        }));

    const Identity stubServerIdentity = Identity::generate();
    const Key stubServerSealing = Key::generateSealing();
    const Key stubNodeSealing = Key::generateSealing();
    bazarish::teststub::Tunnel tunnelStub(
        server, stubServerIdentity, stubServerSealing, ServerCard::Service::eMessaging);
    bazarish::teststub::Tunnel nodeTunnelStub(
        server, stubServerIdentity, stubNodeSealing, ServerCard::Service::eServiceNode);
    const int port = server.start();
    CHECK(port > 0);

    ServerEndpoint endpoint;
    endpoint.serverFingerprint = stubServerIdentity.fingerprint();
    endpoint.facades = {Facade{"127.0.0.1", port}};

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
        const std::unique_ptr<Session> alice = Session::create(aDir, AccountKind::eUser, endpoint, std::string{});
        const std::unique_ptr<Session> bob = Session::create(bDir, AccountKind::eUser, endpoint, std::string{});
        const ResolverCoordinate resolver{resolverRoot.fingerprint(), kTestResolverDest};
        alice->setResolverCoordinate(resolver);
        bob->setResolverCoordinate(resolver);
        const Identity aliceIdentity
            = Identity::fromPrivatePem(AccountDb(aDir, std::string{}).text("identity.pem"));
        const fs::path earlyBundle = fs::temp_directory_path() / "bz-pass-early.bundle";
        fs::remove(earlyBundle);
        alice->exportAccount(earlyBundle, "bundle-password");
        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.destFor[alice->fingerprint()] = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            m.destFor[bob->fingerprint()] = "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
        }

        alice->setSwitchedOff(true);
        bool announceRefused = false;
        try {
            alice->registerAccount();
        } catch (const std::exception&) {
            announceRefused = true;
        }
        CHECK(announceRefused);
        alice->setSwitchedOff(false);

        alice->registerAccount();
        bob->registerAccount();

        CHECK(!alice->inviteUri().empty());
        CHECK(alice->inviteUri().find(m.destFor[alice->fingerprint()]) != std::string::npos);
        CHECK(!bob->inviteUri().empty());

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
            if (found == m.certFor.end()) {
                outcome.errorCode = "CARD_UNKNOWN";
                return outcome;
            }
            outcome.ok = true;
            outcome.sealed = fromBase64(found->second);
            return outcome;
        };
        alice->setFetchTransport(directDial);
        bob->setFetchTransport(directDial);

        const Key ackSigning = Key::generateSigning();
        const auto courierFor = [&m, &ackSigning]() {
            return std::make_unique<OutboundCourier>([](const std::string&, const std::string&) { return true; },
                [&m, &ackSigning](const std::string&,
                    std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                    return std::make_shared<MockServerStream>(m, ackSigning);
                });
        };
        alice->setOutboundCourier(courierFor());
        bob->setOutboundCourier(courierFor());

        alice->addByInvite(bob->inviteUri(), "hi bob");
        bob->sync();
        bob->acceptContactRequest(alice->fingerprint());
        alice->sync();
        CHECK(alice->hasContact(bob->fingerprint()));
        CHECK(bob->hasContact(alice->fingerprint()));

        CHECK(waitFor([&]() {
            alice->sync();
            return alice->canWriteTo(bob->fingerprint());
        }));

        CHECK(alice->aliasNames().empty());
        alice->serviceAliases();
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.resolverStatusCalls == 0);
            CHECK(m.resolverUpdateCalls == 0);
        }

        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasOwner["alice"] = alice->fingerprint();
        }
        CHECK(alice->refreshAliasStatus());
        CHECK(alice->aliasNames().size() == 1);
        CHECK(alice->aliasNames().front().alias == "alice");

        CHECK(!alice->aliasNames().front().bindingWanted);
        CHECK(!alice->aliasUpdatePending());
        const int updatesBeforeAsking = m.resolverUpdateCalls;
        alice->serviceAliases();
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.resolverUpdateCalls == updatesBeforeAsking);
            CHECK(m.aliasDescriptor.count("alice") == 0);
        }

        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasBindingWanted.insert("alice");
        }
        CHECK(alice->refreshAliasStatus());
        CHECK(alice->aliasNames().front().bindingWanted);
        CHECK(alice->aliasUpdatePending());
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.count("alice") == 0);
        }
        CHECK(alice->pushAliasDescriptor());
        CHECK(!alice->aliasUpdatePending());
        const int updatesBeforePressingAgain = m.resolverUpdateCalls;
        CHECK(!alice->pushAliasDescriptor());
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.resolverUpdateCalls == updatesBeforePressingAgain);
            CHECK(m.aliasDescriptor.at("alice").fingerprint == alice->fingerprint());
        }

        {
            const std::lock_guard<std::mutex> lock(m.mu);
            m.aliasBindingWanted.erase("alice");
            m.aliasDescriptor.erase("alice");
        }
        CHECK(alice->refreshAliasStatus());
        CHECK(!alice->aliasNames().front().bindingWanted);
        CHECK(!alice->aliasUpdatePending());
        {
            const std::lock_guard<std::mutex> lock(m.mu);
            m.aliasBindingWanted.insert("alice");
        }
        CHECK(alice->refreshAliasStatus());
        CHECK(alice->aliasNames().front().bindingWanted);
        CHECK(!alice->aliasNames().front().bound);
        CHECK(alice->aliasUpdatePending());
        CHECK(alice->pushAliasDescriptor());
        CHECK(!alice->aliasUpdatePending());
        {
            const std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.at("alice").fingerprint == alice->fingerprint());
        }

        // A name somebody else owns is not repointed by asking nicely.
        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasOwner["bob"] = bob->fingerprint();
        }
        CHECK(bob->aliasNames().empty());
        const int statusBefore = m.resolverStatusCalls;
        CHECK(bob->refreshAliasStatus());
        CHECK(m.resolverStatusCalls == statusBefore + 1);
        CHECK(bob->aliasNames().size() == 1);
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.count("bob") == 0);
            CHECK(m.aliasDescriptor.at("alice").fingerprint == alice->fingerprint());
        }

        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasBindingWanted.insert("bob");
        }
        const int bobStatusBefore = m.resolverStatusCalls;
        const Session::AliasErrandResult errand
            = Session::runAliasErrand(bob->aliasErrandContext());
        CHECK(errand.ok);
        CHECK(errand.haveStatus);
        CHECK(errand.pointed);
        CHECK(m.resolverStatusCalls == bobStatusBefore + 1);
        bob->applyAliasErrand(errand);
        CHECK(bob->aliasNames().size() == 1);
        CHECK(!bob->aliasUpdatePending());
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.at("bob").fingerprint == bob->fingerprint());
        }
        CHECK(bob->canWriteTo(alice->fingerprint()));
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.registered[alice->fingerprint()].size() == 1);
            CHECK(m.registered[bob->fingerprint()].size() == 1);
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
            alice->sendMessage(bob->fingerprint(), "logged");
            CHECK(waitFor([&]() { return logHas(alice->connectionLog(), "text to", "stored"); }));
            const std::vector<WireEvent> aliceLog = alice->connectionLog();
            CHECK(logHas(aliceLog, "text to", "sending"));
            CHECK(logHas(aliceLog, "POST /v1/messaging/", "200"));
            for (const WireEvent& event : aliceLog) {
                CHECK(event.what.find("logged") == std::string::npos);
                CHECK(event.detail.find("logged") == std::string::npos);
            }
            bob->sync();
            CHECK(logHas(bob->connectionLog(), "text from", {}));

            const std::size_t waiting = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[bob->fingerprint()].size();
            }();
            alice->sendMessage(bob->fingerprint(), "outlives a failed ack");
            CHECK(waitFor([&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[bob->fingerprint()].size() > waiting;
            }));
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.failAcks = 1;
            }
            const auto carries = [](const std::vector<IncomingMessage>& taken) {
                return std::count_if(taken.begin(), taken.end(), [](const IncomingMessage& item) {
                    return item.text == "outlives a failed ack";
                });
            };
            CHECK(carries(bob->sync()) == 1);
            CHECK(carries(bob->sync()) == 0);
            {
                std::lock_guard<std::mutex> lock(m.mu);
                CHECK(m.failAcks == 0);
                CHECK(m.mailbox[bob->fingerprint()].size() == waiting);
            }
            alice->setDisplayName("Alice of the log");
            CHECK(logHas(alice->connectionLog(),
                "POST /v1/messaging/self (device.account-name)", "200"));
        }

        {
            const Bytes opus{'O', 'p', 'u', 's'};
            alice->sendVoice(bob->fingerprint(), opus, 2500);
            bool heard = false;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    if (item.contentType == "audio") {
                        heard = true;
                        CHECK(item.attachmentMime == "audio/opus");
                        CHECK(item.attachmentDurationMs == 2500);
                        CHECK(item.attachmentSize == opus.size());
                    }
                }
                return heard;
            }));
            CHECK(heard);
        }

        {
            const fs::path forwardedFile = fs::temp_directory_path() / "bz-pass-forwarded.txt";
            std::ofstream(forwardedFile) << "fwd";
            alice->sendPicture(
                bob->fingerprint(), Bytes{'P', 'N', 'G'}, "p.png", "image/png", {}, {}, {}, true);
            alice->sendFile(bob->fingerprint(), forwardedFile.string(), {}, {}, {}, true);
            alice->sendPicture(bob->fingerprint(), Bytes{'J', 'P', 'G'}, "own.jpg", "image/jpeg");
            std::map<std::string, bool> marks;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    if (item.contentType == "image" || item.contentType == "file") {
                        marks[item.attachmentName] = item.forwarded;
                    }
                }
                return marks.size() >= 3;
            }));
            CHECK(marks.size() == 3);
            CHECK(marks["p.png"]);
            CHECK(marks["bz-pass-forwarded.txt"]);
            CHECK(!marks["own.jpg"]);
            fs::remove(forwardedFile);
        }

        {
            constexpr std::int64_t kPastTheAnswerWindowMs = 6 * 60 * 1000;
            std::mutex seenMutex;
            std::vector<TransferEvent> seen;
            bob->setTransferHandler([&](const TransferEvent& event) {
                const std::lock_guard<std::mutex> lock(seenMutex);
                seen.push_back(event);
            });
            const auto failures = [&]() {
                const std::lock_guard<std::mutex> lock(seenMutex);
                return std::count_if(seen.begin(), seen.end(), [](const TransferEvent& event) {
                    return event.state == TransferState::eFailed;
                });
            };
            const std::size_t before = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice->fingerprint()].size();
            }();
            const std::int64_t askedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                                               .count();
            bob->requestFile(alice->fingerprint(), "never-announced", toHex(sha256(Bytes{'u'})),
                fileTargetAt(fs::temp_directory_path() / "bz-pass-unanswered.bin"));
            bob->expireFileRequests(askedAtMs);
            CHECK(failures() == 0);
            bob->expireFileRequests(askedAtMs + kPastTheAnswerWindowMs);
            CHECK(failures() == 1);
            bob->expireFileRequests(askedAtMs + kPastTheAnswerWindowMs);
            CHECK(failures() == 1);
            CHECK(waitFor([&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice->fingerprint()].size() >= before + 2;
            }));
            bob->setTransferHandler({});
            alice->sync();
        }

        {
            constexpr std::size_t kBelowTheLimitBytes = 1024;
            const Bytes nearTheLimit(kMaxMessagePayloadBytes - kBelowTheLimitBytes, 'x');
            CHECK_THROWS(alice->sendPicture(
                bob->fingerprint(), nearTheLimit, "near.png", "image/png"));
        }

        {
            alice->setAvatar(Bytes(kAvatarMaxBytes, 'a'), "image/jpeg");
            std::size_t received = 0;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    if (item.contentType == "avatar") {
                        received = item.avatarData.size();
                    }
                }
                return received != 0;
            }));
            CHECK(received == kAvatarMaxBytes);
        }

        {
            const InlineKeyboard keyboard{
                {{"Ping", "ping", {}}, {"Time", "time", {}}},
                {{"Help", {}, "help"}},
            };
            alice->sendInteractive(bob->fingerprint(), "pick one", keyboard);
            std::string received;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    if (item.contentType == "text" && item.text == "pick one") {
                        received = item.keyboardJson;
                    }
                }
                return !received.empty();
            }));
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
                alice->sendMessage(bob->fingerprint(), "a->b " + std::to_string(aliceSent));
                ++aliceSent;
                bob->sendMessage(alice->fingerprint(), "b->a " + std::to_string(bobSent));
                ++bobSent;
            }
            CHECK(alice->canWriteTo(bob->fingerprint()));
            CHECK(bob->canWriteTo(alice->fingerprint()));
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.registered[alice->fingerprint()].size() == 1);
            CHECK(m.registered[bob->fingerprint()].size() == 1);
        }
        alice->sync();
        bob->sync();

        {
            const auto weighOf = [&](const std::string& text) {
                const std::size_t before = [&]() {
                    std::lock_guard<std::mutex> lock(m.mu);
                    return m.mailbox[bob->fingerprint()].size();
                }();
                alice->sendMessage(bob->fingerprint(), text);
                CHECK(waitFor([&]() {
                    std::lock_guard<std::mutex> lock(m.mu);
                    return m.mailbox[bob->fingerprint()].size() > before;
                }));
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[bob->fingerprint()].back().payload.size();
            };
            constexpr std::size_t kSealFramingWobble = 8;
            const std::size_t brief = weighOf("hi");
            const std::size_t again = weighOf("hi");
            const std::size_t lengthy = weighOf(std::string(200, 'x'));
            const auto withinWobble = [](const std::size_t a, const std::size_t b) {
                return a < b ? b - a <= kSealFramingWobble : a - b <= kSealFramingWobble;
            };
            CHECK(withinWobble(brief, again));
            CHECK(withinWobble(brief, lengthy));
        }
        bob->sync();

        {
            alice->replaceOwnAddress();
            CHECK(waitFor([&]() {
                alice->flushPendingEchoes();
                return alice->routingFanout().contacts.empty();
            }));
            bool sawRouting = false;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    CHECK(item.contentType != "unsupported");
                    if (item.contentType == "contact.routing") {
                        sawRouting = true;
                    }
                }
                return sawRouting;
            }));
        }

        {
            ContactCard cardBeforeMove;
            const AddressKeys keysBefore = alice->addressKeys();
            {
                std::lock_guard<std::mutex> lock(m.mu);
                cardBeforeMove = ContactCard::verify(fromBase64(m.certFor.at(alice->fingerprint())));
                m.registered.erase(alice->fingerprint());
                m.delegated.erase(alice->fingerprint());
                m.sealingFor.erase(alice->fingerprint());
                m.certFor.erase(alice->fingerprint());
            }
            alice->registerAccount();
            {
                std::lock_guard<std::mutex> lock(m.mu);
                CHECK(m.sealingFor.at(alice->fingerprint()) == keysBefore.sealingPem);
                CHECK(m.registered.at(alice->fingerprint()).size() == 1);
                const ContactCard moved
                    = ContactCard::verify(fromBase64(m.certFor.at(alice->fingerprint())));
                CHECK(moved.dest == cardBeforeMove.dest);
                CHECK(moved.servingSealingKeyDer == cardBeforeMove.servingSealingKeyDer);
                CHECK(moved.servingSealingKeyDer
                    == Key::fromPrivatePem(keysBefore.sealingPem).publicDer());
            }
            CHECK(alice->routingFanout().contacts.empty());
            bob->sendMessage(alice->fingerprint(), "on the new server");
            bool arrived = false;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : alice->sync()) {
                    arrived = arrived || item.text == "on the new server";
                }
                return arrived;
            }));
            for (const IncomingMessage& item : bob->sync()) {
                CHECK(item.contentType != "contact.routing");
            }
        }

        {
            const std::string ref = toHex(randomBytes(8));
            alice->sendReaction(bob->fingerprint(), ref, "\xf0\x9f\x91\x8d");
            alice->sendReceipt(bob->fingerprint(), ref);
            alice->sendDelete(bob->fingerprint(), ref);
            bob->sync();
            CHECK(alice->canWriteTo(bob->fingerprint()));
        }

        {
            CHECK_THROWS(alice->sendChatTimer(bob->fingerprint(), kSecondsPerHour + 1));
            alice->sendChatTimer(bob->fingerprint(), kDaysPerWeek * kSecondsPerDay);
            bool sawTimer = false;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    if (item.contentType == "chat.timer") {
                        sawTimer = true;
                        CHECK(item.timerSeconds == kDaysPerWeek * kSecondsPerDay);
                        CHECK(!item.sentByUs);
                    }
                }
                return sawTimer;
            }));
        }

        {
            const Bytes face = {0xFF, 0xD8, 0xFF, 0xE0, 'j', 'p', 'g'};
            alice->setAvatar(face, "image/jpeg");
            bob->sync();
            CHECK(bob->contactAvatar(alice->fingerprint()) == face);

            alice->setAvatar({}, {});
            CHECK(alice->avatar().empty());
            bob->sync();
            CHECK(bob->contactAvatar(alice->fingerprint()).empty());
        }

        {
            constexpr std::size_t kBacklog = 12;
            const std::string kBacklogText = "backlog ";
            for (std::size_t i = 0; i < kBacklog; ++i) {
                bob->sendMessage(alice->fingerprint(), kBacklogText + std::to_string(i));
            }
            CHECK(waitFor([&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice->fingerprint()].size() >= kBacklog;
            }));
            std::size_t fetchesBefore = 0;
            std::size_t acksBefore = 0;
            {
                std::lock_guard<std::mutex> lock(m.mu);
                fetchesBefore = m.fetches[alice->fingerprint()];
                acksBefore = m.acks[alice->fingerprint()];
            }
            std::size_t taken = 0;
            for (const IncomingMessage& item : alice->sync()) {
                taken += item.text.rfind(kBacklogText, 0) == 0 ? 1 : 0;
            }
            CHECK(taken == kBacklog);
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.fetches[alice->fingerprint()] == fetchesBefore + 1);
            CHECK(m.acks[alice->fingerprint()] == acksBefore + 1);
            CHECK(m.mailbox[alice->fingerprint()].empty());
        }

        {
            const auto deviceItems = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                std::size_t count = 0;
                for (const Mock::Item& item : m.mailbox[alice->fingerprint()]) {
                    count += item.cls == "device" ? 1 : 0;
                }
                return count;
            };
            const auto sendToBob = [&](const std::string& text) {
                const std::size_t before = [&]() {
                    std::lock_guard<std::mutex> lock(m.mu);
                    return m.mailbox[bob->fingerprint()].size();
                }();
                alice->sendMessage(bob->fingerprint(), text);
                CHECK(waitFor([&]() {
                    std::lock_guard<std::mutex> lock(m.mu);
                    return m.mailbox[bob->fingerprint()].size() > before;
                }));
                alice->flushPendingEchoes();
            };

            alice->setDeviceSync(false);
            const std::size_t quiet = deviceItems();
            sendToBob("nobody else to tell");
            alice->syncChatPinToSelf(bob->fingerprint(), true);
            alice->syncReadToSelf(bob->fingerprint(), 1);
            CHECK(deviceItems() == quiet);

            alice->setDeviceSync(true);
            sendToBob("told to the other devices");
            CHECK(waitFor([&]() {
                alice->flushPendingEchoes();
                return deviceItems() > quiet;
            }));
            bob->sync();
        }

        {
            constexpr std::int64_t kMembers = 7;
            constexpr std::int64_t kBlockAt = 1234;
            constexpr std::int64_t kPostSentAt = 1111;
            alice->setGroupBlockSource([&](const std::string& peer) {
                CHECK(peer == bob->fingerprint());
                return GroupBlock{GroupKind::eChannel, kMembers, false, true, kBlockAt};
            });
            RelayedPost post;
            post.type = "text";
            post.id = "group-post-1";
            post.sentAt = kPostSentAt;
            post.text = "relayed";
            post.replyTo = "group-post-0";
            post.author = "Ann";
            post.contactable = true;
            RelayedPost hostPost;
            hostPost.type = "text";
            hostPost.id = "group-post-2";
            hostPost.sentAt = kPostSentAt;
            hostPost.text = "from the host";
            hostPost.fromHost = true;
            RelayedPost counts;
            counts.kind = RelayKind::eReactions;
            counts.id = "group-counts-1";
            counts.reactions
                = nlohmann::json::array({{{"ref", "group-post-1"}, {"counts", {{"+", 2}}}}});
            CHECK(alice->relayFitter()({post, hostPost, counts}) == 3);
            alice->relayPosts(bob->fingerprint(), {post, hostPost, counts});
            alice->sendGroupState(bob->fingerprint());
            alice->sendMessage(bob->fingerprint(), "plain");

            std::map<std::string, IncomingMessage> seen;
            std::vector<std::string> order;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    const std::string key = item.contentType == "text" ? item.text : item.contentType;
                    seen[key] = item;
                    order.push_back(key);
                }
                return seen.size() >= 5;
            }));
            CHECK(seen.size() == 5);
            const auto relayedAt = std::find(order.begin(), order.end(), "relayed");
            CHECK(relayedAt != order.end() && std::next(relayedAt) != order.end()
                && *std::next(relayedAt) == "from the host");
            const IncomingMessage& relayed = seen["relayed"];
            CHECK(relayed.e2eId == "group-post-1");
            CHECK(relayed.sentAt == kPostSentAt);
            CHECK(relayed.replyTo == "group-post-0");
            CHECK(relayed.author == "Ann");
            CHECK(relayed.contactable);
            CHECK(!relayed.fromHost);
            CHECK(seen["from the host"].fromHost);
            CHECK(seen["from the host"].author.empty());
            CHECK(!seen["from the host"].contactable);
            CHECK(relayed.group.has_value());
            CHECK(relayed.group->kind == GroupKind::eChannel);
            CHECK(relayed.group->members == kMembers);
            CHECK(!relayed.group->write);
            CHECK(relayed.group->admin);
            CHECK(relayed.group->at == kBlockAt);
            CHECK(seen["group.state"].group.has_value());
            CHECK(nlohmann::json::parse(seen["group.reactions"].groupReactionsJson)
                      .at(0).at("counts").at("+") == 2);
            CHECK(seen["plain"].group.has_value());
            CHECK(seen["plain"].author.empty());
            CHECK(!seen["plain"].fromHost);

            RelayedPost oversized = post;
            oversized.type = "image";
            oversized.media = Bytes(kMaxMessagePayloadBytes, 0);
            oversized.mediaName = "big.png";
            oversized.mime = "image/png";
            CHECK(alice->relayFitter()({oversized}) == 0);
            CHECK(alice->relayFitter()({post, oversized, hostPost}) == 1);
            RelayedPost third = oversized;
            third.media = Bytes(kMaxMessagePayloadBytes / 3, 0);
            CHECK(alice->relayFitter()({third, third, third, post}) == 2);

            RelayedPost again = post;
            again.id = "group-post-3";
            again.text = "in two envelopes";
            RelayedPost later = post;
            later.id = "group-post-4";
            later.text = "only in the longer one";
            alice->relayPosts(bob->fingerprint(), {post, again});
            alice->relayPosts(bob->fingerprint(), {post, again, later});
            bool sawLater = false;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    sawLater = sawLater || item.text == "only in the longer one";
                }
                return sawLater;
            }));
            CHECK(sawLater);

            alice->setGroupBlockSource({});
            alice->sendMessage(bob->fingerprint(), "no longer a group");
            bool plain = false;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    if (item.text == "no longer a group") {
                        plain = true;
                        CHECK(!item.group.has_value());
                    }
                }
                return plain;
            }));
            CHECK(plain);
        }

        {
            alice->sendMessage(alice->fingerprint(), "note to self");

            std::size_t deviceItems = 0;
            {
                std::lock_guard<std::mutex> lock(m.mu);
                for (const Mock::Item& item : m.mailbox[alice->fingerprint()]) {
                    deviceItems += item.cls == "device" ? 1 : 0;
                }
            }
            CHECK(deviceItems >= 1);

            nlohmann::json saved = {
                {"v", 1},
                {"type", "device.saved"},
                {"id", "saved-1"},
                {"from", alice->fingerprint()},
                {"sentAt", 1},
                {"device", "someotherdevice"},
                {"message",
                    {
                        {"v", 1},
                        {"type", "text"},
                        {"id", "kept-1"},
                        {"from", alice->fingerprint()},
                        {"sentAt", 1},
                        {"text", "note to self"},
                    }},
            };
            {
                signAuthorship(saved, aliceIdentity, /*withKeys=*/false);
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({"saved-echo", "device",
                    hybrid::seal(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({saved}))),
                        Key::fromPublicDer(fromBase64(alice->sealingPublicB64())))});
            }
            bool sawSaved = false;
            for (const IncomingMessage& item : alice->sync()) {
                if (item.fromFingerprint == alice->fingerprint() && item.text == "note to self") {
                    sawSaved = true;
                    CHECK(item.sentByUs);
                }
            }
            CHECK(sawSaved);

            bool refused = false;
            try {
                alice->sendFile(alice->fingerprint(), (aDir / "meta").string(), "", {}, "");
            } catch (const std::exception&) {
                refused = true;
            }
            CHECK(refused);
        }

        {
            alice->renameContact(bob->fingerprint(), "Saved messages");
            CHECK(alice->contactDisplayName(bob->fingerprint()) == "(Contact) Saved messages");
            alice->renameContact(bob->fingerprint(), "  saved MESSAGES  ");
            CHECK(alice->contactDisplayName(bob->fingerprint()) == "(Contact)   saved MESSAGES  ");
            alice->renameContact(bob->fingerprint(), "Bob");
            CHECK(alice->contactDisplayName(bob->fingerprint()) == "Bob");
        }

        {
            CHECK(alice->contactCalls(bob->fingerprint()));
            CHECK(alice->contactNotifications(bob->fingerprint()));
            alice->setContactCalls(bob->fingerprint(), false);
            alice->setContactNotifications(bob->fingerprint(), false);
            CHECK(!alice->contactCalls(bob->fingerprint()));
            CHECK(!alice->contactNotifications(bob->fingerprint()));
            alice->setContactCalls(bob->fingerprint(), true);
            alice->setContactNotifications(bob->fingerprint(), true);
        }

        {
            bob->sendMessage(alice->fingerprint(), "before the block");
            alice->setBlocked(bob->fingerprint(), true);
            CHECK(alice->isBlocked(bob->fingerprint()));
            CHECK(alice->blockedPeers().size() == 1);

            bob->sendMessage(alice->fingerprint(), "after the block");
            bool heardBlocked = false;
            for (const IncomingMessage& item : alice->sync()) {
                if (item.text == "after the block") {
                    heardBlocked = true;
                }
            }
            CHECK(!heardBlocked);
            {
                std::lock_guard<std::mutex> lock(m.mu);
                CHECK(m.mailbox[alice->fingerprint()].empty());
            }

            bool sendRefused = false;
            try {
                alice->sendMessage(bob->fingerprint(), "still there?");
            } catch (const std::exception&) {
                sendRefused = true;
            }
            CHECK(sendRefused);

            const auto held = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.registered[alice->fingerprint()].size();
            };
            CHECK(held() == 0);

            alice->setBlocked(bob->fingerprint(), false);
            CHECK(!alice->isBlocked(bob->fingerprint()));
            CHECK(held() == 1);
            CHECK(bob->canWriteTo(alice->fingerprint()));

            {
                const auto refuseOnce = [&](const std::string& code) {
                    {
                        std::lock_guard<std::mutex> lock(m.mu);
                        m.refuseWith = code;
                    }
                    try {
                        alice->sendMessage(bob->fingerprint(), "into a refusal");
                    } catch (const std::exception&) {
                    }
                    std::lock_guard<std::mutex> lock(m.mu);
                    m.refuseWith.clear();
                };
                for (const char* code :
                    {"STORAGE_FULL", "RECIPIENT_SERVER_UNREACHABLE", "DELIVERY_REJECTED"}) {
                    refuseOnce(code);
                    alice->sync();
                    CHECK(alice->canWriteTo(bob->fingerprint()));
                }
                alice->sendMessage(bob->fingerprint(), "and this one goes");
            }

            bob->sendMessage(alice->fingerprint(), "after the unblock");
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : alice->sync()) {
                    if (item.text == "after the unblock") {
                        return true;
                    }
                }
                return false;
            }));
        }

        {
            const Identity bobIdentity
                = Identity::fromPrivatePem(AccountDb(bDir, std::string{}).text("identity.pem"));
            const std::string strangerFingerprint = Identity::generate().fingerprint();
            const auto intoAliceMailbox = [&](const std::string& id, nlohmann::json content) {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({id, "content",
                    hybrid::seal(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({content}))),
                        Key::fromPublicDer(fromBase64(alice->sealingPublicB64())))});
            };
            const auto text = [](const std::string& from, const std::string& id,
                                  const std::string& body) {
                return nlohmann::json{{"v", 1}, {"type", "text"}, {"id", id}, {"from", from},
                    {"sentAt", 1}, {"text", body}};
            };

            nlohmann::json forged = text(strangerFingerprint, "forged-1", "trust me, I am them");
            signAuthorship(forged, bobIdentity, /*withKeys=*/true);
            intoAliceMailbox("forged-1", forged);
            intoAliceMailbox("unsigned-1", text(bob->fingerprint(), "unsigned-1", "no signature"));
            nlohmann::json honest = text(bob->fingerprint(), "honest-1", "this one is mine");
            signAuthorship(honest, bobIdentity, /*withKeys=*/false);
            intoAliceMailbox("honest-1", honest);
            nlohmann::json forgedInBatch = text(strangerFingerprint, "forged-2", "slipped in first");
            signAuthorship(forgedInBatch, bobIdentity, /*withKeys=*/true);
            nlohmann::json honestInBatch = text(bob->fingerprint(), "honest-2", "after a forged one");
            signAuthorship(honestInBatch, bobIdentity, /*withKeys=*/false);
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({"mixed-1", "content",
                    hybrid::seal(padToLadder(nlohmann::json::to_cbor(
                                     nlohmann::json::array({forgedInBatch, honestInBatch}))),
                        Key::fromPublicDer(fromBase64(alice->sealingPublicB64())))});
            }

            const std::string plantedPeer = Identity::generate().fingerprint();
            const auto deviceNotice = [&](const std::string& id, nlohmann::json extra) {
                extra["v"] = 1;
                extra["id"] = id;
                extra["from"] = bob->fingerprint();
                extra["sentAt"] = 1;
                extra["device"] = "not-a-device-of-hers";
                signAuthorship(extra, bobIdentity, /*withKeys=*/false);
                intoAliceMailbox(id, extra);
            };
            const std::int64_t termBefore = alice->delegationDays();
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
            bool sawForgedInBatch = false;
            bool sawHonestInBatch = false;
            for (const IncomingMessage& item : alice->sync()) {
                sawForged = sawForged || item.text == "trust me, I am them";
                sawUnsigned = sawUnsigned || item.text == "no signature";
                sawHonest = sawHonest || item.text == "this one is mine";
                sawForgedInBatch = sawForgedInBatch || item.text == "slipped in first";
                sawHonestInBatch = sawHonestInBatch || item.text == "after a forged one";
            }
            CHECK(!sawForgedInBatch);
            CHECK(sawHonestInBatch);
            CHECK(!sawForged);
            CHECK(alice->delegationDays() == termBefore);
            CHECK(!alice->hasContact(plantedPeer));
            CHECK(!sawUnsigned);
            CHECK(sawHonest);
        }

        {
            const fs::path cDir = fs::temp_directory_path() / "bz-pass-c";
            fs::remove(cDir);
            const std::unique_ptr<Session> carol = Session::create(cDir, AccountKind::eUser, endpoint, std::string{});
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[carol->fingerprint()]
                    = "flkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            }
            carol->registerAccount();
            carol->setFetchTransport(directDial);
            carol->setOutboundCourier(courierFor());

            const std::string longestName(kMaxAccountNameBytes, 'n');
            alice->setDisplayName(longestName);
            CHECK(alice->displayName() == longestName);
            const std::string longestGreeting(kMaxContactGreetingBytes, 'g');
            alice->addByInvite(carol->inviteUri(), longestGreeting);

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
            const std::unique_ptr<Session> dana = Session::create(dDir, AccountKind::eUser, endpoint, std::string{});
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[dana->fingerprint()]
                    = "glkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            }
            dana->registerAccount();
            dana->setFetchTransport(directDial);
            dana->setOutboundCourier(courierFor());

            const auto heldForAlice = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice->fingerprint()].size();
            };
            const std::size_t beforeAdding = heldForAlice();
            alice->addByInvite(dana->inviteUri(), "let me in");
            bool askedTwice = true;
            try {
                alice->addByInvite(dana->inviteUri(), "let me in again");
            } catch (const std::exception&) {
                askedTwice = false;
            }
            CHECK(!askedTwice);
            const std::size_t beforeRequests = heldForAlice();
            CHECK(beforeRequests == beforeAdding + 1);
            CHECK(alice->hasContact(dana->fingerprint()));
            CHECK(waitFor([&]() {
                dana->sync();
                return dana->contactIsPending(alice->fingerprint());
            }));
            CHECK(dana->hasContact(alice->fingerprint()));
            CHECK(dana->contactIsPending(alice->fingerprint()));
            CHECK(heldForAlice() == beforeRequests);

            dana->sendReceipt(alice->fingerprint(), "whatever-they-sent");
            CHECK(heldForAlice() == beforeRequests);

            dana->acceptContactRequest(alice->fingerprint());
            CHECK(dana->contactIsPending(alice->fingerprint()));
            CHECK(dana->contactAcceptInFlight(alice->fingerprint()));
            dana->acceptContactRequest(alice->fingerprint());
            CHECK(waitFor([&]() { return heldForAlice() > beforeRequests; }));
            CHECK(waitFor([&]() {
                dana->sync();
                return !dana->contactIsPending(alice->fingerprint());
            }));
            CHECK(!dana->contactIsPending(alice->fingerprint()));
            CHECK(!dana->contactAcceptInFlight(alice->fingerprint()));

            alice->removeContact(dana->fingerprint());
            CHECK(!alice->hasContact(dana->fingerprint()));
            const std::size_t beforeReturn = heldForAlice();
            alice->addByInvite(dana->inviteUri(), "me again");
            CHECK(waitFor([&]() {
                dana->sync();
                return dana->contactAcceptInFlight(alice->fingerprint());
            }));
            CHECK(waitFor([&]() { return heldForAlice() > beforeReturn; }));
            CHECK(waitFor([&]() {
                dana->sync();
                return !dana->contactIsPending(alice->fingerprint());
            }));
            CHECK(!dana->contactIsPending(alice->fingerprint()));
            CHECK(waitFor([&]() {
                alice->sync();
                return alice->canWriteTo(dana->fingerprint());
            }));
        }

        {
            const fs::path eDir = fs::temp_directory_path() / "bz-pass-e";
            fs::remove(eDir);
            const std::unique_ptr<Session> erin = Session::create(eDir, AccountKind::eUser, endpoint, std::string{});
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[erin->fingerprint()]
                    = "hlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            }
            erin->registerAccount();
            erin->setFetchTransport(directDial);
            erin->setOutboundCourier(courierFor());

            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.refuseWith = "CONTACT_RATE_LIMITED";
            }
            CHECK_THROWS(alice->addByInvite(erin->inviteUri(), "refused"));
            CHECK(!alice->hasContact(erin->fingerprint()));
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.refuseWith.clear();
            }

            DeliverySchedule once;
            once.attempts = 1;
            once.dial = std::chrono::seconds(1);
            once.run = std::chrono::seconds(2);
            alice->setOutboundCourier(std::make_unique<OutboundCourier>(
                [](const std::string&, const std::string&) { return true; },
                [](const std::string&, std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                    return nullptr;
                },
                once));
            CHECK_THROWS(alice->addByInvite(erin->inviteUri(), "are you there"));
            CHECK(alice->contactAwaitsAnswer(erin->fingerprint()));

            alice->setOutboundCourier(courierFor());
            alice->sendContactRequest(erin->fingerprint(), "resent-request", "are you there",
                DeliveryWatch{}, /*waitForOutcome=*/true);
            CHECK(waitFor([&]() {
                erin->sync();
                return erin->hasContact(alice->fingerprint());
            }));
            CHECK(erin->contactIsPending(alice->fingerprint()));
            erin->acceptContactRequest(alice->fingerprint());
            CHECK(waitFor([&]() {
                alice->sync();
                return alice->canWriteTo(erin->fingerprint());
            }));
            CHECK(!alice->contactAwaitsAnswer(erin->fingerprint()));
        }

        {
            const Bytes face = {0xFF, 0xD8, 0xFF, 0xE0, 'b', 'o', 'b'};
            bob->setAvatar(face, "image/jpeg");
            CHECK(waitFor([&]() {
                alice->sync();
                return !alice->contactAvatar(bob->fingerprint()).empty();
            }));
            CHECK(alice->contactAvatar(bob->fingerprint()) == face);
            alice->renameContact(bob->fingerprint(), "Bob of the book");

            const fs::path secondDir = fs::temp_directory_path() / "bz-pass-a-second.db";
            fs::remove(secondDir);
            Session::importAccount(earlyBundle, secondDir, "bundle-password");
            const std::unique_ptr<Session> second = Session::open(secondDir, std::string{});
            CHECK(second->fingerprint() == alice->fingerprint());
            CHECK(!second->hasContact(bob->fingerprint()));

            second->sync();
            alice->sync();
            CHECK(waitFor([&]() {
                second->sync();
                return second->hasContact(bob->fingerprint());
            }));
            CHECK(second->hasContact(bob->fingerprint()));
            CHECK(second->contactDisplayName(bob->fingerprint()) == "Bob of the book");
            CHECK(second->contactAvatar(bob->fingerprint()) == face);
            CHECK(second->canWriteTo(bob->fingerprint()));
            alice->publishRouting();
            CHECK(waitFor([&]() {
                second->sync();
                return second->hasI2pDestination();
            }));
            CHECK(second->i2pAddress() == alice->i2pAddress());
            CHECK(second->addressKeys().sealingPem == alice->addressKeys().sealingPem);
            CHECK(second->addressKeys().signingPem == alice->addressKeys().signingPem);
            alice->issueAddressKeys();
            alice->publishRouting();
            CHECK(waitFor([&]() {
                second->sync();
                return second->addressKeys().sealingPem == alice->addressKeys().sealingPem;
            }));
            CHECK(second->addressKeys().signingPem == alice->addressKeys().signingPem);
            CHECK(waitFor([&]() {
                alice->flushPendingEchoes();
                return alice->routingFanout().contacts.empty();
            }));
            bool bobHeardKeys = false;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    bobHeardKeys = bobHeardKeys || item.contentType == "contact.routing";
                }
                return bobHeardKeys;
            }));
            bob->sendMessage(alice->fingerprint(), "hello, second device");
            bool sawBob = false;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : second->sync()) {
                    sawBob = sawBob || item.text == "hello, second device";
                }
                return sawBob;
            }));
            CHECK(sawBob);

            {
                const fs::path fDir = fs::temp_directory_path() / "bz-pass-f";
                fs::remove(fDir);
                const std::unique_ptr<Session> finn = Session::create(fDir, AccountKind::eUser, endpoint, std::string{});
                {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    m.destFor[finn->fingerprint()]
                        = "hlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
                }
                finn->registerAccount();
                finn->setFetchTransport(directDial);
                finn->setOutboundCourier(courierFor());

                alice->addByInvite(finn->inviteUri(), "added on one device");
                alice->renameContact(finn->fingerprint(), "Finn of the phone");
                CHECK(waitFor([&]() {
                    second->sync();
                    return second->hasContact(finn->fingerprint());
                }));
                CHECK(second->hasContact(finn->fingerprint()));
                CHECK(waitFor([&]() {
                    finn->sync();
                    return finn->contactIsPending(alice->fingerprint());
                }));
                finn->acceptContactRequest(alice->fingerprint());
                finn->sendMessage(alice->fingerprint(), "seen on the other device too");
                bool sawFinn = false;
                CHECK(waitFor([&]() {
                    for (const IncomingMessage& item : second->sync()) {
                        sawFinn = sawFinn || item.text == "seen on the other device too";
                    }
                    return sawFinn;
                }));
                CHECK(sawFinn);
                CHECK(second->contactDisplayName(finn->fingerprint()) == "Finn of the phone");
            }

            {
                Bytes huge(200 * 1024, 0x41);
                std::copy(kJpegOpening.begin(), kJpegOpening.end(), huge.begin());
                bob->setAvatar(huge, "image/jpeg");
                CHECK(waitFor([&]() {
                    alice->sync();
                    return alice->contactAvatar(bob->fingerprint()) == huge;
                }));
                CHECK(alice->contactAvatar(bob->fingerprint()) == huge);

                const fs::path thirdDir = fs::temp_directory_path() / "bz-pass-a-third.db";
                fs::remove(thirdDir);
                Session::importAccount(earlyBundle, thirdDir, "bundle-password");
                const std::unique_ptr<Session> third = Session::open(thirdDir, std::string{});
                third->sync();
                alice->sync();
                CHECK(waitFor([&]() {
                    third->sync();
                    return third->hasContact(bob->fingerprint());
                }));
                CHECK(third->hasContact(bob->fingerprint()));
                CHECK(third->contactAvatar(bob->fingerprint()).empty());
                CHECK(third->contactDisplayName(bob->fingerprint()) == "Bob of the book");
            }

            const std::size_t before = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice->fingerprint()].size();
            }();
            second->sync();
            const std::size_t after = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice->fingerprint()].size();
            }();
            CHECK(after <= before);
            alice->sync();
            second->sync();
            CHECK(second->hasContact(bob->fingerprint()));
            CHECK(second->contactDisplayName(bob->fingerprint()) == "Bob of the book");

            CHECK(alice->canWriteTo(bob->fingerprint()));
            const fs::path laterBundle = fs::temp_directory_path() / "bz-pass-later.bundle";
            fs::remove(laterBundle);
            alice->exportAccount(laterBundle, "bundle-password");
            CHECK(alice->canWriteTo(bob->fingerprint()));

            const fs::path fourthDir = fs::temp_directory_path() / "bz-pass-a-fourth.db";
            fs::remove(fourthDir);
            Session::importAccount(laterBundle, fourthDir, "bundle-password");
            const std::unique_ptr<Session> fourth = Session::open(fourthDir, std::string{});
            CHECK(fourth->hasContact(bob->fingerprint()));
            CHECK(fourth->canWriteTo(bob->fingerprint()));
            fourth->sync();
            CHECK(fourth->canWriteTo(bob->fingerprint()));
        }

        {
            const auto fromAnotherDevice = [&](nlohmann::json notice) {
                signAuthorship(notice, aliceIdentity, /*withKeys=*/false);
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({"self-" + notice.at("id").get<std::string>(),
                    "device",
                    hybrid::seal(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({notice}))),
                        Key::fromPublicDer(fromBase64(alice->sealingPublicB64())))});
            };
            std::int64_t noticeClock = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                                           .count();
            const auto stamp = [&noticeClock]() { return ++noticeClock; };
            const auto notice = [&](const std::string& type, nlohmann::json extra) {
                extra["v"] = 1;
                extra["type"] = type;
                if (!extra.contains("id")) {
                    extra["id"] = type;
                }
                extra["from"] = alice->fingerprint();
                if (!extra.contains("sentAt")) {
                    extra["sentAt"] = stamp();
                }
                extra["device"] = "someotherdevice";
                return extra;
            };

            CHECK(alice->displayName() != "renamed elsewhere");
            fromAnotherDevice(notice("device.account-name", {{"name", "renamed elsewhere"}}));
            alice->sync();
            CHECK(alice->displayName() == "renamed elsewhere");

            CHECK(alice->acceptCalls());
            CHECK(alice->sendReceipts());
            fromAnotherDevice(notice("device.account-prefs",
                {{"acceptCalls", false}, {"sendReceipts", false}}));
            alice->sync();
            CHECK(!alice->acceptCalls());
            CHECK(!alice->sendReceipts());
            fromAnotherDevice(notice("device.account-prefs", {{"acceptCalls", true}}));
            alice->sync();
            CHECK(alice->acceptCalls());
            CHECK(!alice->sendReceipts());
            alice->setSendReceipts(true);

            fromAnotherDevice(notice("device.contact-prefs",
                {{"peer", bob->fingerprint()}, {"notifications", false}, {"allowCalls", false}}));
            alice->sync();
            CHECK(!alice->contactNotifications(bob->fingerprint()));
            CHECK(!alice->contactCalls(bob->fingerprint()));

            const std::string stranger = std::string(52, 'y');
            fromAnotherDevice(notice("device.contact-block",
                {{"peer", stranger}, {"blocked", true}}));
            alice->sync();
            CHECK(alice->isBlocked(stranger));
            fromAnotherDevice(notice("device.contact-block",
                {{"peer", stranger}, {"blocked", false}}));
            alice->sync();
            CHECK(!alice->isBlocked(stranger));

            const std::int64_t earlier = stamp();
            const std::int64_t later = stamp();
            fromAnotherDevice(notice("device.contact-block",
                {{"peer", stranger}, {"blocked", true}, {"sentAt", later}, {"id", "block-later"}}));
            alice->sync();
            CHECK(alice->isBlocked(stranger));
            fromAnotherDevice(notice("device.contact-block", {{"peer", stranger}, {"blocked", false},
                {"sentAt", earlier}, {"id", "unblock-replayed"}}));
            alice->sync();
            CHECK(alice->isBlocked(stranger));
            fromAnotherDevice(notice("device.contact-block",
                {{"peer", stranger}, {"blocked", false}, {"id", "unblock-now"}}));
            alice->sync();
            CHECK(!alice->isBlocked(stranger));

            fromAnotherDevice(notice("device.chat-clear", {{"peer", bob->fingerprint()}}));
            bool sawClear = false;
            for (const IncomingMessage& item : alice->sync()) {
                if (item.contentType == "device.chat-clear") {
                    sawClear = true;
                    CHECK(item.refId == bob->fingerprint());
                }
            }
            CHECK(sawClear);

            CHECK(alice->hasContact(bob->fingerprint()));
            fromAnotherDevice(notice("device.contact-remove", {{"peer", bob->fingerprint()}}));
            bool sawRemove = false;
            for (const IncomingMessage& item : alice->sync()) {
                if (item.contentType == "device.contact-remove") {
                    sawRemove = true;
                    CHECK(item.refId == bob->fingerprint());
                }
            }
            CHECK(sawRemove);
            CHECK(!alice->hasContact(bob->fingerprint()));
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
                m.mailbox[alice->fingerprint()].push_back({"stranger-blob", "content",
                    hybrid::seal(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({inner}))),
                        Key::fromPublicDer(fromBase64(alice->sealingPublicB64())))});
            }
            for (const IncomingMessage& item : alice->sync()) {
                CHECK(item.fromFingerprint != stranger);
            }
            CHECK(!alice->hasContact(stranger));
        }

        {
            const Identity sneak = Identity::generate();
            const nlohmann::json bootstrap = {{"kind", "user"},
                {"sealing", toBase64(Key::generateSealing().publicDer())},
                {"dest", std::string(52, 'q') + ".b32.i2p"},
                {"servingKey", toBase64(Key::generateSealing().publicDer())},
                {"pass", toBase64(randomBytes(kSneakPassBytes))},
                {"presenceKey", toBase64(Key::generateX25519().publicDer())},
                {"presenceDest", std::string(52, 'r') + ".b32.i2p"}};
            nlohmann::json request = {{"v", 1}, {"type", "contact.request"}, {"id", "sneak-request"},
                {"from", sneak.fingerprint()}, {"sentAt", 1}, {"text", "hello"}, {"dn", "Sneak"},
                {"bootstrap", bootstrap}};
            signAuthorship(request, sneak, /*withKeys=*/true);
            nlohmann::json invite = {{"v", 1}, {"type", "call.invite"}, {"id", "sneak-call"},
                {"from", sneak.fingerprint()}, {"sentAt", 1}, {"callId", "sneak-call-id"}};
            signAuthorship(invite, sneak, /*withKeys=*/false);
            const auto deliver = [&](const std::string& id, const std::string& cls,
                                     const std::vector<nlohmann::json>& items) {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({id, cls,
                    hybrid::seal(padToLadder(nlohmann::json::to_cbor(nlohmann::json(items))),
                        Key::fromPublicDer(fromBase64(alice->sealingPublicB64())))});
            };
            const auto fromSneak = [&]() {
                std::size_t count = 0;
                for (const IncomingMessage& item : alice->sync()) {
                    count += item.fromFingerprint == sneak.fingerprint() ? 1 : 0;
                }
                return count;
            };

            deliver("sneak-both", kContactDeliveryClass, {request, invite});
            CHECK(fromSneak() == 0);
            CHECK(!alice->hasContact(sneak.fingerprint()));

            deliver("sneak-asks", kContactDeliveryClass, {request});
            CHECK(fromSneak() == 1);
            CHECK(alice->contactIsPending(sneak.fingerprint()));
            deliver("sneak-rings", "content", {invite});
            CHECK(fromSneak() == 0);
            CHECK(alice->currentCall().state == Session::CallState::eIdle);
            CHECK(alice->contactIsPending(sneak.fingerprint()));
            alice->removeContact(sneak.fingerprint());
        }

        {
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.refuseWith = "RECIPIENT_SERVER_UNREACHABLE";
            }
            int refused = 0;
            alice->setRoutingFanoutSink([&refused](const std::string&, const bool delivered) {
                if (!delivered) {
                    ++refused;
                }
            });
            alice->announceNewRouting();
            const std::size_t queued = alice->routingFanout().contacts.size();
            CHECK(queued > 0);
            CHECK(waitFor([&]() {
                alice->flushPendingEchoes();
                return static_cast<std::size_t>(refused) == queued;
            }));
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.refuseWith.clear();
            }
            CHECK(alice->routingFanout().contacts.size() == queued);
            for (const std::string& peer : alice->routingFanout().contacts) {
                CHECK(alice->canWriteTo(peer));
            }
            CHECK(alice->routingFanout().registry);
            alice->setRoutingFanoutSink({});
        }

        {
            constexpr std::chrono::seconds kServingWithin{60};
            constexpr std::chrono::seconds kStopWithin{2};
            constexpr std::chrono::milliseconds kServingPoll{50};
            const fs::path gDir = fs::temp_directory_path() / "bz-pass-g";
            fs::remove(gDir);
            std::unique_ptr<Session> gail
                = Session::create(gDir, AccountKind::eUser, endpoint, std::string{});
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[gail->fingerprint()]
                    = "klkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            }
            gail->registerAccount();
            gail->setFetchTransport(directDial);
            gail->setOutboundCourier(courierFor());
            gail->addByInvite(bob->inviteUri(), "a file for you");
            bob->sync();
            bob->acceptContactRequest(gail->fingerprint());
            CHECK(waitFor([&]() {
                gail->sync();
                return gail->canWriteTo(bob->fingerprint());
            }));

            const fs::path scratch = gDir.parent_path() / ".transfers";
            const auto servingFiles = [&scratch]() {
                std::set<std::string> names;
                if (!fs::exists(scratch)) {
                    return names;
                }
                for (const fs::directory_entry& entry : fs::directory_iterator(scratch)) {
                    const std::string name = entry.path().filename().string();
                    if (name.rfind("file-serve-", 0) == 0) {
                        names.insert(name);
                    }
                }
                return names;
            };
            const std::set<std::string> earlier = servingFiles();
            const fs::path offered = fs::temp_directory_path() / "bz-pass-offered.bin";
            std::ofstream(offered, std::ios::binary) << "a file nobody comes for";
            std::atomic<int> waiting{0};
            gail->setTransferHandler([&waiting](const TransferEvent& event) {
                if (event.stage == TransferStage::eWaiting) {
                    ++waiting;
                }
            });
            std::atomic<int> fetching{0};
            bob->setTransferHandler([&fetching](const TransferEvent& event) {
                if (event.stage == TransferStage::eConnecting) {
                    ++fetching;
                }
            });
            gail->sendFile(bob->fingerprint(), offered.string());
            IncomingMessage announced;
            CHECK(waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    if (item.contentType == "file"
                        && item.attachmentName == offered.filename().string()) {
                        announced = item;
                    }
                }
                return !announced.e2eId.empty();
            }));
            const FileTarget copy
                = fileTargetAt(fs::temp_directory_path() / "bz-pass-offered-copy.bin");
            bob->requestFile(gail->fingerprint(), announced.e2eId, announced.attachmentRef, copy);

            const Identity gailIdentity
                = Identity::fromPrivatePem(AccountDb(gDir, std::string{}).text("identity.pem"));
            FileOffer elsewhere;
            elsewhere.fileId = announced.e2eId;
            elsewhere.host = std::string(52, 'w') + ".b32.i2p";
            elsewhere.header = Bytes{1};
            elsewhere.key = "key";
            elsewhere.sha256 = announced.attachmentRef;
            elsewhere.size = 1;
            nlohmann::json unasked = {{"v", 1}, {"type", "file.offer"}, {"id", "unasked-offer"},
                {"from", gail->fingerprint()},
                {"sentAt",
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count()},
                {"offer", fileOfferToJson(elsewhere)}, {"forAsk", "not-the-ask"}};
            signAuthorship(unasked, gailIdentity, /*withKeys=*/false);
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[bob->fingerprint()].push_back({"unasked-offer", "content",
                    hybrid::seal(
                        padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({unasked}))),
                        Key::fromPublicDer(fromBase64(bob->sealingPublicB64())))});
            }
            bool offerSeen = false;
            for (const IncomingMessage& item : bob->sync()) {
                offerSeen = offerSeen || item.contentType == "file.offer";
            }
            CHECK(offerSeen);
            CHECK(fetching.load() == 0);

            const auto servingBy = std::chrono::steady_clock::now() + kServingWithin;
            const auto serveUntil = [&](const int count) {
                int round = 0;
                while (waiting.load() < count && std::chrono::steady_clock::now() < servingBy) {
                    gail->setDisplayName("Gail " + std::to_string(++round));
                    gail->sendMessage(bob->fingerprint(), "while serving");
                    gail->sync();
                    std::this_thread::sleep_for(kServingPoll);
                }
                return waiting.load() >= count;
            };
            const auto heldNow = [&]() {
                std::set<std::string> held;
                for (const std::string& name : servingFiles()) {
                    if (earlier.count(name) == 0) {
                        held.insert(name);
                    }
                }
                return held;
            };
            CHECK(serveUntil(1));
            CHECK(heldNow().size() == 1);

            bob->requestFile(gail->fingerprint(), announced.e2eId, announced.attachmentRef, copy);
            CHECK(serveUntil(2));
            const auto oneBy = std::chrono::steady_clock::now() + kStopWithin;
            while (heldNow().size() > 1 && std::chrono::steady_clock::now() < oneBy) {
                std::this_thread::sleep_for(kServingPoll);
            }
            const std::set<std::string> held = heldNow();
            CHECK(held.size() == 1);

            const auto stopping = std::chrono::steady_clock::now();
            gail.reset();
            CHECK(std::chrono::steady_clock::now() - stopping < kStopWithin);
            for (const std::string& name : held) {
                CHECK(!fs::exists(scratch / name));
            }
            bob->setTransferHandler({});
            fs::remove(offered);
            fs::remove(gDir);
        }
    }

    {
        const std::unique_ptr<Session> reopened = Session::open(aDir, std::string{});
        CHECK(!reopened->routingFanout().contacts.empty());
        CHECK(reopened->routingFanout().registry);
        for (const std::string& peer : reopened->routingFanout().contacts) {
            CHECK(reopened->canWriteTo(peer));
        }
    }

    server.stop();
    gatewayServer.stop();
    fs::remove_all(aDir);
    fs::remove_all(bDir);

    std::fprintf(stderr, "TestDeliveryPass passed (bob sent %d, alice sent %d)\n", bobSent, aliceSent);
    return 0;
}
