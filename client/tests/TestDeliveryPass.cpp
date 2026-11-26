// Bazarish project (c) 2026
#include "GatewayAddress.hpp"
#include "ResolverStub.hpp"
#include "I2pKeys.hpp"
#include "I2pRouter.hpp"
#include "Client.hpp"
#include "OutboundCourier.hpp"
#include "MailWaitGate.hpp"
#include "AccountDb.hpp"
#include "AccountKey.hpp"
#include "KeyedDatabase.hpp"
#include "Authorship.hpp"
#include "PresenceSeed.hpp"
#include "FailureCause.hpp"
#include "Session.hpp"
#include "WireLog.hpp"

#include "FakeGateway.hpp"
#include "DeviceTestKit.hpp"
#include "PageScan.hpp"
#include "TunnelStub.hpp"

#include <bazarish/AliasMaintenance.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/FederationFrame.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Padding.hpp>
#include <bazarish/Pass.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/ServerDescriptor.hpp>

#include <bazarish/HttpServer.hpp>

#include "TestUtil.hpp"

#include <functional>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <array>
#include <iterator>
#include <limits>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace {

namespace fs = std::filesystem;

std::string requireDevice(const http::Request& request)
{
    return request.header(bazarish::teststub::kCallerDeviceHeader);
}

Bytes callerCert(const http::Request& request)
{
    return fromBase64(request.header(bazarish::teststub::kCallerCertHeader));
}

DeviceCredential deviceOf(const fs::path& accountDir)
{
    const AccountDb db(accountDir, std::string{});
    return DeviceCredential(
        Identity::fromPrivatePem(db.text("device-signing.pem")), *db.get("device-cert"));
}

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
constexpr std::size_t kB33LabelChars = 56;
constexpr int kQuietPasses = 3;
constexpr std::size_t kShortReaderBytes = 31;
constexpr std::array<std::uint8_t, 3> kJpegOpening{0xFF, 0xD8, 0xFF};
constexpr const char* kPoisonItemId = "poison";
constexpr std::size_t kPoisonItemBytes = 64;
constexpr int kFailingPasses = 2;

void respondJson(http::Response& response, const nlohmann::json& body)
{
    response.contentType = "application/json";
    response.body = body.dump();
}

constexpr const char* kTestResolverDest
    = "flkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";

struct Mock {
    std::mutex mu;
    std::map<std::string, std::string> sealingFor;
    std::map<std::string, std::string> destFor;
    std::map<std::string, std::string> certFor;  // fingerprint -> contact card (base64 DER)
    std::map<std::string, Bytes> cardKeyFor;
    std::set<std::string> delegated;
    std::set<std::string> signedUp;
    struct Item {
        Item(std::string itemId, std::string itemClass, Bytes itemPayload, std::string to = {})
            : id(std::move(itemId))
            , cls(std::move(itemClass))
            , payload(std::move(itemPayload))
            , forDevice(std::move(to))
        {
        }

        std::string id;
        std::string cls;
        Bytes payload;
        std::string forDevice;
        std::set<std::string> ackedBy;
    };
    std::map<std::string, std::vector<Item>> mailbox;
    std::map<std::string, std::size_t> fetches;
    std::map<std::string, std::size_t> acks;
    std::map<std::string, std::set<std::string>> registered;
    // Account, then device, to the install token it registered with.
    std::map<std::string, std::map<std::string, std::string>> installs;
    struct Listed {
        Bytes cert;
        Bytes sealing;
        Bytes departure;
    };
    std::map<std::string, std::map<std::string, Listed>> listed;
    std::map<std::string, std::uint64_t> devicesVersion;

    void dropTaken(const std::string& account)
    {
        std::vector<Item>& box = mailbox[account];
        const std::map<std::string, std::string>& readers = installs[account];
        std::erase_if(box, [&readers](const Item& item) {
            if (!item.forDevice.empty()) {
                return item.ackedBy.contains(item.forDevice);
            }
            return std::all_of(readers.begin(), readers.end(),
                [&item](const auto& reader) { return item.ackedBy.contains(reader.first); });
        });
    }
    std::map<std::string, std::set<std::string>> seenIds;
    std::size_t largestContactRequest = 0;
    int nextId = 1;
    std::string refuseWith;
    bool refusePassRegistration = false;
    int failAcks = 0;
    // Stored, then the stream ends before the reply: what a sender sees of a lost ack.
    std::string loseReplyTo;
    std::map<std::string, int> offers;
    std::map<std::string, std::string> aliasOwner;
    std::map<std::string, Descriptor> aliasDescriptor;
    std::set<std::string> aliasBindingWanted;
    int resolverStatusCalls = 0;
    int resolverUpdateCalls = 0;
};

class MockServerStream final : public DeliveryStream {
public:
    MockServerStream(Mock& mock, const Key& signingKey)
        : mock_(mock)
        , signingKey_(signingKey)
    {
    }

    void writeAll(const ByteView data) override { written_.append(data.begin(), data.end()); }

    std::size_t readSome(const ByteBuffer buffer) override
    {
        if (!served_) {
            reply_ = serve();
            served_ = true;
        }
        const ByteView from
            = viewOf(reply_).subspan(sent_, std::min(buffer.size(), reply_.size() - sent_));
        std::copy(from.begin(), from.end(), buffer.begin());
        sent_ += from.size();
        return from.size();
    }

    bool answered() const override { return true; }

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
                return hybrid::unseal(sealed, Key::fromPrivatePem(pem)).bytes();
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
            ++mock_.offers[deliveryId];
            if (!mock_.loseReplyTo.empty() && mock_.loseReplyTo == deliveryId) {
                mock_.loseReplyTo.clear();
                return {};
            }
        }
        const Bytes signedBytes = deliveryAckInput(deliveryId);
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
    bool served_ = false;
    std::size_t sent_ = 0;
};

// A stream into a lease set whose tunnels are gone: takes everything, answers nothing.
class SilentServerStream final : public DeliveryStream {
public:
    void writeAll(ByteView) override {}

    std::size_t readSome(ByteBuffer) override
    {
        std::unique_lock<std::mutex> lock(mutex_);
        closed_.wait(lock, [this]() { return shut_; });
        throw std::runtime_error("closed before an answer");
    }

    bool answered() const override { return false; }

    void close() override
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            shut_ = true;
        }
        closed_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable closed_;
    bool shut_ = false;
};

void addByInvite(Session& session, const std::string& invite, const std::string& text)
{
    Session::ContactCardRequest request;
    request.uriOrAlias = invite;
    request.introText = text;
    const Session::ContactCardResolved resolved = Session::resolveContactCard(
        session.contactFetchContext(), request, [](Session::CardStep) {});
    if (!resolved.ok) {
        throw std::runtime_error(resolved.error);
    }
    std::mutex mutex;
    std::optional<OutboundCourier::Outcome> settled;
    DeliveryWatch watch;
    watch.onOutcome = [&mutex, &settled](const OutboundCourier::Outcome& outcome) {
        const std::lock_guard<std::mutex> lock(mutex);
        settled = outcome;
    };
    session.commitContactAdd(resolved, watch);
    CHECK(testutil::waitFor([&mutex, &settled]() {
        const std::lock_guard<std::mutex> lock(mutex);
        return settled.has_value();
    }));
    session.settleContactRequest(resolved.fingerprint, *settled);
    if (!settled->stored) {
        throw std::runtime_error(settled->errorMessage);
    }
}

}  // namespace

int main()
try {
    bazarish::setSelfHostedFacadeOnLoopback(true);
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
            if (m.certFor.count(caller) == 0) {
                response.status = 404;
                respondJson(response,
                    {{"error",
                        {{"code", "ACCOUNT_UNKNOWN"},
                            {"message", "this server serves no such account"}}}});
                return;
            }
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
              CHECK(bazarish::isB32I2pHost(card.dest));
              {
                  std::lock_guard<std::mutex> lock(m.mu);
                  if (m.signedUp.count(caller) == 0) {
                      response.status = 404;
                      respondJson(response,
                          {{"error",
                              {{"code", "ACCOUNT_UNKNOWN"},
                                  {"message", "no pending registration"}}}});
                      return;
                  }
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
                  m.cardKeyFor[caller] = linkKeyFromText(
                      nlohmann::json::parse(request.body).at("cardKey").get<std::string>());
                  std::map<std::string, std::string>& installs = m.installs[caller];
                  std::erase_if(installs,
                      [&card](const auto& entry) { return card.revocation.revokes(entry.first); });
                  if (std::erase_if(m.listed[caller],
                          [&card](const auto& entry) { return card.revocation.revokes(entry.first); })
                      > 0) {
                      ++m.devicesVersion[caller];
                  }
                  m.dropTaken(caller);
              }
              respondJson(response, {{"quotaBytes", 100u * 1024 * 1024}, {"approval", "approved"},
                  {"held", false}, {"registrationMessage", ""}});
          };
    server.post("/v1/account/card", stub(handlePublishCard));

    server.post("/v1/account/registration",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            std::lock_guard<std::mutex> lock(m.mu);
            m.signedUp.insert(caller);
            respondJson(response, {{"ok", true}});
        }));

    server.get("/v1/account/i2p-status",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            std::lock_guard<std::mutex> lock(m.mu);
            if (m.signedUp.count(caller) == 0) {
                response.status = 404;
                respondJson(response,
                    {{"error", {{"code", "ACCOUNT_UNKNOWN"}, {"message", "no account"}}}});
                return;
            }
            respondJson(response, {{"approval", "approved"}, {"held", false}, {"registrationMessage", ""}});
        }));

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
            const std::string to = body.value("to", std::string());
            Mock::Item item{body.at("deliveryId").get<std::string>(), "device",
                fromBase64(body.at("payload").get<std::string>()), to};
            if (to.empty()) {
                item.ackedBy.insert(requireDevice(request));
            }
            m.mailbox[caller].push_back(std::move(item));
            m.dropTaken(caller);
            respondJson(response, {{"ok", true}});
        }));

    // Under the lock: what the account's published card says of the device.
    const auto revokedHere = [&m](const std::string& account, const std::string& device) {
        const auto card = m.certFor.find(account);
        return card != m.certFor.end() && !card->second.empty()
            && ContactCard::verify(fromBase64(card->second)).revocation.revokes(device);
    };
    const auto refuseRevoked = [](http::Response& response) {
        response.status = 403;
        respondJson(response,
            {{"error", {{"code", "DEVICE_REVOKED"}, {"message", "this device was revoked"}}}});
    };

    server.post("/v1/messaging/clients",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const std::string device = requireDevice(request);
            const std::string install
                = nlohmann::json::parse(request.body).at("install").get<std::string>();
            std::lock_guard<std::mutex> lock(m.mu);
            if (revokedHere(caller, device)) {
                refuseRevoked(response);
                return;
            }
            if (m.listed[caller].contains(device) && !m.listed[caller].at(device).departure.empty()) {
                response.status = 409;
                respondJson(response,
                    {{"error", {{"code", "DEVICE_TAKEN"}, {"message", "it left"}}}});
                return;
            }
            const auto [held, added] = m.installs[caller].emplace(device, install);
            if (!added && held->second != install) {
                response.status = 409;
                respondJson(response,
                    {{"error", {{"code", "DEVICE_TAKEN"}, {"message", "another copy"}}}});
                return;
            }
            const Bytes sealing = fromBase64(
                nlohmann::json::parse(request.body).at("sealing").get<std::string>());
            CHECK(DeviceCertificate::verify(callerCert(request)).sealsWith(sealing));
            if (added) {
                m.listed[caller][device] = {callerCert(request), sealing, {}};
                ++m.devicesVersion[caller];
            }
            respondJson(response, {{"ok", true}});
        }));

    server.get(kEventsPath,
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const std::string device = requireDevice(request);
            std::lock_guard<std::mutex> lock(m.mu);
            nlohmann::json pending = nlohmann::json::array();
            for (const Mock::Item& item : m.mailbox[caller]) {
                if ((!item.forDevice.empty() && item.forDevice != device)
                    || item.ackedBy.contains(device)) {
                    continue;
                }
                pending.push_back(
                    {{"id", item.id}, {"class", item.cls}, {"bytes", item.payload.size()}});
            }
            respondJson(response, {{"pending", pending}, {"usedBytes", 0}, {"quotaBytes", 0},
                {"devicesVersion", m.devicesVersion[caller]}});
        }));

    server.get("/v1/messaging/devices",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            std::lock_guard<std::mutex> lock(m.mu);
            nlohmann::json devices = nlohmann::json::array();
            for (const auto& [device, entry] : m.listed[caller]) {
                devices.push_back({{"cert", toBase64(entry.cert)}, {"sealing", toBase64(entry.sealing)},
                    {"registered", m.installs[caller].contains(device)},
                    {"departure", toBase64(entry.departure)}});
            }
            respondJson(response, {{"version", m.devicesVersion[caller]}, {"devices", devices},
                {"card", m.certFor.contains(caller) ? m.certFor.at(caller) : std::string()}});
        }));

    server.post("/v1/messaging/departure",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const std::string device = requireDevice(request);
            const Bytes departure = fromBase64(
                nlohmann::json::parse(request.body).at("departure").get<std::string>());
            DeviceDeparture::verify(departure, DeviceCertificate::verify(callerCert(request)));
            std::lock_guard<std::mutex> lock(m.mu);
            m.installs[caller].erase(device);
            m.listed[caller].at(device).departure = departure;
            ++m.devicesVersion[caller];
            m.dropTaken(caller);
            respondJson(response, {{"ok", true}});
        }));

    server.del("/v1/messaging/clients/{id}",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const std::string device = request.captures.at(0);
            CHECK(device != requireDevice(request));
            CHECK(DeviceCertificate::verify(callerCert(request)).role == DeviceRole::ePrimary);
            std::lock_guard<std::mutex> lock(m.mu);
            m.installs[caller].erase(device);
            ++m.devicesVersion[caller];
            m.dropTaken(caller);
            respondJson(response, {{"ok", true}});
        }));

    server.post("/v1/messaging/passes",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const nlohmann::json passes = nlohmann::json::parse(request.body).at("passes");
            std::lock_guard<std::mutex> lock(m.mu);
            if (m.refusePassRegistration) {
                response.status = kServiceUnavailable;
                return;
            }
            for (const nlohmann::json& handle : passes) {
                m.registered[caller].insert(handle.get<std::string>());
            }
            respondJson(response, {{"ok", true}});
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
            respondJson(response, {{"ok", true}});
        }));

    server.get("/v1/messaging/pending",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const std::string device = requireDevice(request);
            std::lock_guard<std::mutex> lock(m.mu);
            if (revokedHere(caller, device)) {
                refuseRevoked(response);
                return;
            }
            nlohmann::json pending = nlohmann::json::array();
            for (const Mock::Item& item : m.mailbox[caller]) {
                if ((!item.forDevice.empty() && item.forDevice != device)
                    || item.ackedBy.contains(device)) {
                    continue;
                }
                pending.push_back(
                    {{"id", item.id}, {"class", item.cls}, {"bytes", item.payload.size()}});
            }
            respondJson(response, {{"pending", pending}});
        }));

    server.post("/v1/messaging/fetch",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string caller = requireCaller(request);
            const std::string device = requireDevice(request);
            const nlohmann::json ids = nlohmann::json::parse(request.body).at("ids");
            std::lock_guard<std::mutex> lock(m.mu);
            nlohmann::json items = nlohmann::json::array();
            for (const nlohmann::json& id : ids) {
                for (const Mock::Item& item : m.mailbox[caller]) {
                    if (item.id == id.get<std::string>()
                        && (item.forDevice.empty() || item.forDevice == device)) {
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
            for (const nlohmann::json& id : ids) {
                for (Mock::Item& item : m.mailbox[caller]) {
                    if (item.id == id.get<std::string>()) {
                        item.ackedBy.insert(requireDevice(request));
                    }
                }
            }
            m.dropTaken(caller);
            ++m.acks[caller];
            respondJson(response, {{"ok", true}});
        }));

    const Identity stubServerIdentity = Identity::generate();
    const Key stubServerSealing = Key::generateSealing();
    const Key stubNodeSealing = Key::generateSealing();
    bazarish::teststub::Tunnel tunnelStub(
        server, stubServerIdentity, stubServerSealing, ServerCard::Service::eMessaging);
    bazarish::teststub::Tunnel nodeTunnelStub(
        server, stubServerIdentity, stubNodeSealing, ServerCard::Service::eServerService);
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

    const testutil::ScratchDir passScratch("pass");
    const fs::path& scratch = passScratch.path();
    const fs::path aDir = scratch / "a.db";
    const fs::path bDir = scratch / "b.db";

    int bobSent = 0;
    int aliceSent = 0;

    {
        const std::unique_ptr<Session> alice = Session::create(aDir, AccountKind::eUser, endpoint, std::string{});
        const std::unique_ptr<Session> bob = Session::create(bDir, AccountKind::eUser, endpoint, std::string{});
        const ResolverCoordinate resolver{resolverRoot.fingerprint(), kTestResolverDest};
        alice->setResolverCoordinate(resolver);
        bob->setResolverCoordinate(resolver);
        const DeviceCredential aliceIdentity = deviceOf(aDir);
        // What a device of the account has posted to the account's own mailbox.
        const auto postedToSelf = [&](const fs::path& accountDir, const std::string& owner,
                                      const std::string& type) {
            const AccountDb db(accountDir, std::string{});
            const Key sealing = Key::fromPrivatePem(db.text("device-sealing.pem"));
            EpochRing ring;
            ring.addAll(SecretBytes(db.get("epochs").value()));
            const std::string device = deviceOf(accountDir).device();
            const std::lock_guard<std::mutex> lock(m.mu);
            for (const Mock::Item& item : m.mailbox[owner]) {
                if (item.cls != "device" || item.ackedBy.contains(device)
                    || (!item.forDevice.empty() && item.forDevice != device)) {
                    continue;
                }
                const SecretBytes opened = item.forDevice.empty() ? ring.open(item.payload)
                                                                  : hybrid::unseal(item.payload, sealing);
                const nlohmann::json bodies = nlohmann::json::from_cbor(unpadFromLadder(opened).bytes());
                for (const nlohmann::json& body : bodies) {
                    if (body.value("type", std::string()) == type) {
                        return true;
                    }
                }
            }
            return false;
        };
        const auto selfHolds = [&](const std::string& type) {
            return postedToSelf(aDir, alice->fingerprint(), type);
        };
        const fs::path earlyBundle = scratch / "bz-pass-early.bundle";
        fs::remove(earlyBundle);
        alice->exportAccount(earlyBundle, "bundle-password");
        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.destFor[alice->fingerprint()] = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";
            m.destFor[bob->fingerprint()] = "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";
        }

        alice->setSwitchedOff(true);
        bool announceRefused = false;
        try {
            alice->registerAccount();
        } catch (const std::exception&) {
            announceRefused = true;
        }
        CHECK(announceRefused);
        CHECK(alice->registrationUnfinished());
        CHECK(!alice->listedByServer());
        alice->setSwitchedOff(false);

        alice->registerAccount();
        CHECK(!alice->registrationUnfinished());
        CHECK(alice->listedByServer());
        std::vector<ConnectMilestone> milestones;
        setConnectProgressSink(bob->fingerprint(),
            [&milestones](const ConnectMilestone milestone) { milestones.push_back(milestone); });
        bob->registerAccount();
        setConnectProgressSink(bob->fingerprint(), {});
        {
            const auto at = [&milestones](const ConnectMilestone milestone) {
                return std::find(milestones.begin(), milestones.end(), milestone);
            };
            CHECK(at(ConnectMilestone::eRegistering) < at(ConnectMilestone::eRegisteringDevice));
            for (std::size_t i = 1; i < milestones.size(); ++i) {
                CHECK(connectPercent(milestones[i - 1]) <= connectPercent(milestones[i]));
            }
        }
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.signedUp.count(alice->fingerprint()) == 1);
            CHECK(m.signedUp.count(bob->fingerprint()) == 1);
        }

        CHECK(!alice->inviteUri().empty());
        CHECK(alice->inviteUri().find(m.destFor[alice->fingerprint()]) != std::string::npos);
        CHECK(!bob->inviteUri().empty());

        const auto plainDial = [&m, &resolverRoot, &resolverDelegated, &resolverDelegationDer](
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
            (void)resolverRoot;
            std::lock_guard<std::mutex> lock(m.mu);
            FetchOutcome outcome;
            outcome.errorCode = "CARD_UNKNOWN";
            for (const auto& [owner, cardB64] : m.certFor) {
                const Bytes cardDer = fromBase64(cardB64);
                if (ContactCard::verify(cardDer).dest != toDest) {
                    continue;
                }
                const Bytes& cardKey = m.cardKeyFor.at(owner);
                const std::optional<SecretBytes> asked = KeyedSeal(cardKey, kCardRequestLabel).open(query);
                if (!asked.has_value()
                    || cardFetchQueryFromJson(nlohmann::json::parse(asked->bytes())).fingerprint != owner) {
                    return outcome;
                }
                outcome.ok = true;
                outcome.errorCode.clear();
                outcome.sealed = KeyedSeal(cardKey, kCardReplyLabel).seal(cardDer);
                return outcome;
            }
            return outcome;
        };
        ResolverStub resolverChannel(resolverDelegated, resolverDelegationDer);
        const FetchTransport directDial
            = [&](const std::string& toDest, const std::string& op, const Bytes& body) {
                  if (ResolverStub::asks(op)) {
                      return resolverChannel.answer(op, body,
                          [&](const std::string& inner, const Bytes& asked) {
                              return plainDial(toDest, inner, asked);
                          },
                          static_cast<std::int64_t>(std::time(nullptr)));
                  }
                  return plainDial(toDest, op, body);
              };
        std::mutex recordedMutex;
        std::string recorded;
        const FetchTransport recording
            = [&](const std::string& toDest, const std::string& op, const Bytes& body) {
                  const FetchOutcome outcome = directDial(toDest, op, body);
                  const std::lock_guard<std::mutex> lock(recordedMutex);
                  recorded.append(body.begin(), body.end());
                  recorded.append(outcome.sealed.begin(), outcome.sealed.end());
                  recorded.append(outcome.refusal.begin(), outcome.refusal.end());
                  return outcome;
              };
        alice->setFetchTransport(recording);
        bob->setFetchTransport(recording);

        const Key ackSigning = Key::generateSigning();
        const auto courierFor = [&m, &ackSigning]() {
            OutboundCourier::Links links;
            links.prepare = [](const std::string&, const std::string&) { return true; };
            links.openStream = [&m, &ackSigning](const std::string&,
                                   std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                return std::make_shared<MockServerStream>(m, ackSigning);
            };
            return links;
        };
        alice->setOutboundLinks(courierFor());
        bob->setOutboundLinks(courierFor());

        addByInvite(*alice, bob->inviteUri(), "hi bob");
        bob->sync();
        bob->acceptContactRequest(alice->fingerprint());
        alice->sync();
        CHECK(alice->hasContact(bob->fingerprint()));
        CHECK(bob->hasContact(alice->fingerprint()));

        CHECK(testutil::waitFor([&]() {
            alice->sync();
            return alice->canWriteTo(bob->fingerprint());
        }));
        CHECK(parseDescriptor(alice->contactInviteUri(bob->fingerprint())).cardKey
            == parseDescriptor(bob->inviteUri()).cardKey);
        CHECK(parseDescriptor(bob->contactInviteUri(alice->fingerprint())).cardKey
            == parseDescriptor(alice->inviteUri()).cardKey);

        CHECK(alice->aliasNames().empty());
        const auto runErrand = [](Session& session) {
            session.applyAliasErrand(Session::runAliasErrand(session.aliasErrandContext()));
        };

        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasOwner["alice"] = alice->fingerprint();
        }
        runErrand(*alice);
        CHECK(alice->aliasNames().size() == 1);
        CHECK(alice->aliasNames().front().alias == "alice");

        {
            const FetchTransport silent
                = [](const std::string&, const std::string&, const Bytes&) -> FetchOutcome {
                throw FetchFailed(FetchFailure::eNotConnected, "nothing answered in the test");
            };
            const FetchTransport refusing
                = [](const std::string&, const std::string&, const Bytes&) -> FetchOutcome {
                FetchOutcome refused;
                refused.errorCode = "UNAVAILABLE";
                return refused;
            };
            const FetchTransport garbled
                = [](const std::string&, const std::string&, const Bytes&) -> FetchOutcome {
                FetchOutcome answered;
                answered.ok = true;
                answered.sealed = Bytes{1, 2, 3};
                return answered;
            };
            const auto cardFrom = [&alice, &bob](const FetchTransport& transport,
                                      const std::string& invite) {
                Session::ContactFetchContext context = alice->contactFetchContext();
                context.transport = transport;
                Session::ContactCardRequest request;
                request.uriOrAlias = invite.empty() ? bob->inviteUri() : invite;
                return Session::resolveContactCard(context, request, [](Session::CardStep) {});
            };
            const Session::ContactCardResolved unanswered = cardFrom(silent, {});
            CHECK(!unanswered.ok);
            CHECK(unanswered.cause == linkCause(LinkFailure::eServerUnreachable));
            CHECK(unanswered.failedAt == Session::CardStep::eFetchingCard);
            CHECK(cardFrom(refusing, {}).cause == linkCause(LinkFailure::eServerRefused));
            CHECK(cardFrom(garbled, {}).cause == linkCause(LinkFailure::eServerMalformed));
            CHECK(cardFrom(silent, "not an invite").cause
                == localCause(LocalFailure::eInvalidInvite));

            Session::AliasErrandContext errand = alice->aliasErrandContext();
            errand.transport = silent;
            const Session::AliasErrandResult lost = Session::runAliasErrand(errand);
            CHECK(!lost.ok);
            CHECK(lost.cause == linkCause(LinkFailure::eServerUnreachable));
            errand.transport = refusing;
            CHECK(Session::runAliasErrand(errand).cause == linkCause(LinkFailure::eServerRefused));
            errand.resolver = ResolverCoordinate{};
            CHECK(Session::runAliasErrand(errand).cause == localCause(LocalFailure::eNoRegistry));

            const FetchTransport kept = alice->contactFetchContext().transport;
            alice->setFetchTransport(refusing);
            FailureCause bindingRefused;
            try {
                alice->setAliasBinding("alice", true);
            } catch (const std::exception& error) {
                bindingRefused = causeOf(error);
            }
            CHECK(bindingRefused == linkCause(LinkFailure::eServerRefused));
            FailureCause wordRefused;
            try {
                alice->setAliasWord("alice", "secret");
            } catch (const std::exception& error) {
                wordRefused = causeOf(error);
            }
            CHECK(wordRefused == linkCause(LinkFailure::eServerRefused));
            alice->setFetchTransport(kept);
            CHECK(!alice->aliasNames().front().bindingWanted);
        }

        CHECK(!alice->aliasNames().front().bindingWanted);
        CHECK(!alice->aliasUpdatePending());
        const int updatesBeforeAsking = m.resolverUpdateCalls;
        runErrand(*alice);
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.resolverUpdateCalls == updatesBeforeAsking);
            CHECK(m.aliasDescriptor.count("alice") == 0);
        }

        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasBindingWanted.insert("alice");
        }
        runErrand(*alice);
        CHECK(alice->aliasNames().front().bindingWanted);
        CHECK(!alice->aliasUpdatePending());
        const int updatesBeforePressingAgain = m.resolverUpdateCalls;
        runErrand(*alice);
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
        runErrand(*alice);
        CHECK(!alice->aliasNames().front().bindingWanted);
        CHECK(!alice->aliasUpdatePending());
        {
            const std::lock_guard<std::mutex> lock(m.mu);
            m.aliasBindingWanted.insert("alice");
        }
        runErrand(*alice);
        CHECK(alice->aliasNames().front().bindingWanted);
        CHECK(!alice->aliasUpdatePending());
        {
            const std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.at("alice").fingerprint == alice->fingerprint());
        }

        {
            std::lock_guard<std::mutex> lock(m.mu);
            m.aliasOwner["bob"] = bob->fingerprint();
        }
        CHECK(bob->aliasNames().empty());
        const int statusBefore = m.resolverStatusCalls;
        runErrand(*bob);
        CHECK(m.resolverStatusCalls == statusBefore + 1);
        CHECK(bob->aliasNames().size() == 1);
        {
            std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.aliasDescriptor.count("bob") == 0);
            CHECK(m.aliasDescriptor.at("alice").fingerprint == alice->fingerprint());
        }

        {
            const std::lock_guard<std::mutex> lock(recordedMutex);
            CHECK(!recorded.empty());
            for (const std::string& secret :
                {alice->fingerprint(), bob->fingerprint(), std::string("alice")}) {
                CHECK(recorded.find(secret) == std::string::npos);
            }
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
                    if (event.what.starts_with(whatPrefix)
                        && (status.empty() || event.status == status)) {
                        return true;
                    }
                }
                return false;
            };
            alice->sendMessage(bob->fingerprint(), "logged");
            CHECK(testutil::waitFor([&]() { return logHas(alice->connectionLog(), "text to", "stored"); }));
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
            CHECK(testutil::waitFor([&]() {
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
            CHECK(testutil::waitFor([&]() {
                alice->flushPendingEchoes();
                return logHas(alice->connectionLog(), "POST /v1/messaging/self (device.account-name)", "200");
            }));
            {
                std::lock_guard<std::mutex> lock(m.mu);
                CHECK(std::none_of(m.mailbox[alice->fingerprint()].begin(),
                    m.mailbox[alice->fingerprint()].end(),
                    [](const Mock::Item& item) { return item.cls == "device"; }));
            }
        }

        {
            const Bytes opus{'O', 'p', 'u', 's'};
            alice->sendVoice(bob->fingerprint(), opus, 2500);
            bool heard = false;
            CHECK(testutil::waitFor([&]() {
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
            alice->sendMessage(bob->fingerprint(), "anchored", {}, {}, {}, false, "x1");
            alice->sendMessage(bob->fingerprint(), "unanchored");
            std::map<std::string, std::string> afters;
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    if (item.text == "anchored" || item.text == "unanchored") {
                        afters[item.text] = item.after;
                    }
                }
                return afters.size() >= 2;
            }));
            CHECK(afters["anchored"] == "x1");
            CHECK(afters["unanchored"].empty());
        }

        {
            const fs::path forwardedFile = scratch / "bz-pass-forwarded.txt";
            std::ofstream(forwardedFile) << "fwd";
            alice->sendPicture(
                bob->fingerprint(), Bytes{'P', 'N', 'G'}, "p.png", "image/png", {}, {}, {}, true);
            alice->sendFile(bob->fingerprint(), forwardedFile.string(), {}, {}, {}, true);
            alice->sendPicture(bob->fingerprint(), Bytes{'J', 'P', 'G'}, "own.jpg", "image/jpeg");
            std::map<std::string, bool> marks;
            std::string forwardedId;
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    if (item.contentType == "image" || item.contentType == "file") {
                        marks[item.attachmentName] = item.forwarded;
                    }
                    if (item.attachmentName == "bz-pass-forwarded.txt") {
                        forwardedId = item.e2eId;
                    }
                }
                return marks.size() >= 3;
            }));
            CHECK(marks.size() == 3);
            CHECK(marks["p.png"]);
            CHECK(marks["bz-pass-forwarded.txt"]);
            fs::remove(forwardedFile);
            const std::optional<Bytes> carried = bob->fileBytes(forwardedId);
            CHECK(carried.has_value());
            CHECK(std::string(carried->begin(), carried->end()) == "fwd");
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
                fileTargetAt(scratch / "bz-pass-unanswered.bin"));
            bob->expireFileRequests(askedAtMs);
            CHECK(failures() == 0);
            bob->expireFileRequests(askedAtMs + kPastTheAnswerWindowMs);
            CHECK(failures() == 1);
            bob->expireFileRequests(askedAtMs + kPastTheAnswerWindowMs);
            CHECK(failures() == 1);
            CHECK(testutil::waitFor([&]() {
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
            const auto heldForBob = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[bob->fingerprint()].size();
            };
            const std::size_t before = heldForBob();
            alice->setAvatar(Bytes(kAvatarMaxBytes, 'a'), "image/jpeg");
            CHECK(testutil::waitFor([&]() { return heldForBob() > before; }));
            const std::size_t sealed = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[bob->fingerprint()].back().payload.size();
            }();
            std::printf("TestDeliveryPass: the largest avatar message is %zu bytes\n", sealed);
            CHECK(sealed <= kMaxMessagePayloadBytes);
            std::size_t received = 0;
            CHECK(testutil::waitFor([&]() {
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
            CHECK(testutil::waitFor([&]() {
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
                CHECK(testutil::waitFor([&]() {
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
            CHECK(testutil::waitFor([&]() {
                alice->flushPendingEchoes();
                return alice->routingFanout().contacts.empty();
            }));
            bool sawRouting = false;
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    CHECK(item.contentType != "unsupported");
                    if (item.contentType == kTypeAccountCard) {
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
                CHECK(SecretBytes(Bytes(m.sealingFor.at(alice->fingerprint()).begin(),
                          m.sealingFor.at(alice->fingerprint()).end()))
                    == keysBefore.sealingPem);
                CHECK(m.registered.at(alice->fingerprint()).size() == 1);
                const ContactCard moved
                    = ContactCard::verify(fromBase64(m.certFor.at(alice->fingerprint())));
                CHECK(moved.dest == cardBeforeMove.dest);
                CHECK(moved.servingSealingKeyDer == cardBeforeMove.servingSealingKeyDer);
                CHECK(moved.servingSealingKeyDer
                    == Key::fromPrivatePem(std::string(keysBefore.sealingPem.bytes().begin(),
                                               keysBefore.sealingPem.bytes().end()))
                           .publicDer());
            }
            CHECK(alice->routingFanout().contacts.empty());
            bob->sendMessage(alice->fingerprint(), "on the new server");
            bool arrived = false;
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : alice->sync()) {
                    arrived = arrived || item.text == "on the new server";
                }
                return arrived;
            }));
            for (const IncomingMessage& item : bob->sync()) {
                CHECK(item.contentType != kTypeAccountCard);
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
            CHECK(testutil::waitFor([&]() {
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
            CHECK(testutil::waitFor([&]() {
                alice->flushPendingEchoes();
                bob->sync();
                return bob->contactAvatar(alice->fingerprint()) == face;
            }));

            alice->setAvatar({}, {});
            CHECK(alice->avatar().empty());
            CHECK(testutil::waitFor([&]() {
                alice->flushPendingEchoes();
                bob->sync();
                return bob->contactAvatar(alice->fingerprint()).empty();
            }));
        }

        {
            const std::string longest(kStatusMaxChars, 'a');
            CHECK(acceptableStatus(longest));
            CHECK(!acceptableStatus(longest + "a"));
            std::string widest;
            for (std::size_t i = 0; i < kStatusMaxBytes / std::string("\u0436").size(); ++i) {
                widest += "\u0436";
            }
            CHECK(acceptableStatus(widest));
            CHECK(!acceptableStatus(widest + "\u0436"));
            CHECK(!acceptableStatus("tab\there"));
            CHECK_THROWS(alice->setStatus(longest + "a"));

            const std::string status = "first line\nsecond line";
            alice->setStatus(status);
            CHECK(alice->status() == status);
            CHECK(testutil::waitFor([&]() {
                alice->flushPendingEchoes();
                bob->sync();
                return bob->contactStatus(alice->fingerprint()) == status;
            }));

            alice->setStatus({});
            CHECK(alice->status().empty());
            CHECK(testutil::waitFor([&]() {
                alice->flushPendingEchoes();
                bob->sync();
                return bob->contactStatus(alice->fingerprint()).empty();
            }));
            std::printf("TestDeliveryPass: a status reaches the contact and its removal does too\n");
        }

        {
            alice->setSwitchedOff(true);
            CHECK_THROWS(alice->removeContactEverywhere(bob->fingerprint()));
            CHECK(alice->hasContact(bob->fingerprint()));
            CHECK_THROWS(alice->setBlocked(bob->fingerprint(), true));
            CHECK(!alice->isBlocked(bob->fingerprint()));
            alice->setSwitchedOff(false);
            std::printf("TestDeliveryPass: a switched-off account neither removes nor blocks\n");
        }

        {
            const auto idsFor = [&m](const std::string& owner) {
                std::set<std::string> ids;
                const std::lock_guard<std::mutex> lock(m.mu);
                for (const Mock::Item& item : m.mailbox[owner]) {
                    ids.insert(item.id);
                }
                return ids;
            };
            const auto holdsAny = [&idsFor](const std::string& owner, const std::set<std::string>& wanted) {
                const std::set<std::string> held = idsFor(owner);
                return std::any_of(wanted.begin(), wanted.end(),
                    [&held](const std::string& id) { return held.contains(id); });
            };

            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[bob->fingerprint()].push_back(
                    {kPoisonItemId, "content", Bytes(kPoisonItemBytes, 'x')});
            }
            bob->sync();
            CHECK(!holdsAny(bob->fingerprint(), {kPoisonItemId}));

            const auto avatarWritesFail = [&bDir](const bool failing) {
                const Database raw(
                    openKeyed(bDir, accountkey::keyFor(bDir, std::string{})), "test copy");
                raw.run(failing ? "CREATE TRIGGER avatar_write_fails BEFORE INSERT ON state "
                                  "WHEN NEW.name LIKE 'avatar-%' "
                                  "BEGIN SELECT RAISE(ABORT, 'disk full'); END"
                                : "DROP TRIGGER avatar_write_fails");
            };
            const std::set<std::string> before = idsFor(bob->fingerprint());
            const Bytes face = {0xFF, 0xD8, 0xFF, 0xE0, 'd', 'i', 's', 'k'};
            avatarWritesFail(true);
            alice->setAvatar(face, "image/jpeg");
            CHECK(testutil::waitFor([&]() { return idsFor(bob->fingerprint()).size() > before.size(); }));
            std::set<std::string> arrived;
            for (const std::string& id : idsFor(bob->fingerprint())) {
                if (!before.contains(id)) {
                    arrived.insert(id);
                }
            }
            for (int pass = 0; pass < kFailingPasses; ++pass) {
                bool refused = false;
                try {
                    bob->sync();
                } catch (const StorageError&) {
                    refused = true;
                }
                CHECK(refused);
                CHECK(holdsAny(bob->fingerprint(), arrived));
            }
            avatarWritesFail(false);
            CHECK(testutil::waitFor([&]() {
                bob->sync();
                return !holdsAny(bob->fingerprint(), arrived);
            }));
            CHECK(AccountDb(bDir, std::string{}).get("avatar-" + alice->fingerprint()) == face);
        }

        {
            constexpr std::size_t kBacklog = 12;
            const std::string kBacklogText = "backlog ";
            std::atomic<std::size_t> backlogStored{0};
            DeliveryWatch countStored;
            countStored.onOutcome = [&backlogStored](const DeliveryOutcome& outcome) {
                backlogStored += outcome.stored ? 1 : 0;
            };
            for (std::size_t i = 0; i < kBacklog; ++i) {
                bob->sendMessage(alice->fingerprint(), kBacklogText + std::to_string(i), {},
                    countStored);
            }
            CHECK(testutil::waitFor([&]() {
                bob->flushPendingEchoes();
                return backlogStored.load() == kBacklog;
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
                taken += item.text.starts_with(kBacklogText) ? 1 : 0;
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
                CHECK(testutil::waitFor([&]() {
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
            sendToBob("no other device of the account to tell");
            alice->flushPendingEchoes();
            CHECK(deviceItems() == quiet);
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
            RelayedPost roster;
            roster.kind = RelayKind::eMembers;
            roster.id = "group-members-1";
            roster.members.op = MemberListOp::eFull;
            roster.members.part = 1;
            roster.members.parts = 1;
            roster.members.total = 2;
            roster.members.names = {"Ann", "Bob Two"};
            roster.members.you = "Bob Two";
            RelayedPost widest = roster;
            widest.members.names.assign(
                kMaxMemberNamesPerLetter, std::string(kMaxGroupNameBytes, 'n'));
            widest.members.you.clear();
            CHECK(alice->relayFitter()({widest}) == 1);
            RelayedPost widestFile = post;
            widestFile.type = kTypeFile;
            widestFile.id = std::string(kMaxMessageIdBytes, 'i');
            widestFile.replyTo = std::string(kMaxMessageIdBytes, 'r');
            widestFile.after = std::string(kMaxMessageIdBytes, 'a');
            widestFile.author = std::string(kMaxGroupNameBytes, 'n');
            widestFile.media = Bytes(kMaxMediaBytes, 0);
            widestFile.mediaName = std::string(kMaxMediaNameBytes, 'f');
            widestFile.mime = std::string(kMaxMediaMimeBytes, 'm');
            widestFile.sentAt = std::numeric_limits<std::int64_t>::max();
            CHECK(alice->relayFitter()({widestFile}) == 1);
            RelayedPost file = post;
            file.type = kTypeFile;
            file.id = "group-file-1";
            file.media = Bytes{'n', 'o', 't', 'e', 's'};
            file.mediaName = "notes.txt";
            file.mime = "text/plain";
            CHECK(alice->relayFitter()({post, hostPost, counts, roster, file}) == 5);
            alice->relayPosts(bob->fingerprint(), {post, hostPost, counts, roster, file});
            alice->sendGroupState(bob->fingerprint());
            alice->sendMessage(bob->fingerprint(), "plain");

            std::map<std::string, IncomingMessage> seen;
            std::vector<std::string> order;
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    const std::string key = item.contentType == "text" ? item.text : item.contentType;
                    seen[key] = item;
                    order.push_back(key);
                }
                return seen.size() >= 7;
            }));
            CHECK(seen.size() == 7);
            CHECK(seen["file"].e2eId == "group-file-1");
            CHECK(seen["file"].attachmentName == "notes.txt");
            CHECK(seen["file"].author == "Ann");
            CHECK(bob->fileBytes("group-file-1") == file.media);
            const std::optional<MemberListLetter>& list = seen["group.members"].memberList;
            CHECK(list.has_value());
            CHECK(list->op == MemberListOp::eFull);
            CHECK(list->names == (std::vector<std::string>{"Ann", "Bob Two"}));
            CHECK(list->total == 2 && list->part == 1 && list->parts == 1);
            CHECK(list->you == "Bob Two");
            bob->askGroupMembers(alice->fingerprint());
            bool asked = false;
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : alice->sync()) {
                    asked = asked || item.contentType == "group.members.ask";
                }
                return asked;
            }));
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
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    sawLater = sawLater || item.text == "only in the longer one";
                }
                return sawLater;
            }));
            CHECK(sawLater);

            alice->setGroupBlockSource({});
            alice->sendMessage(bob->fingerprint(), "no longer a group");
            bool plain = false;
            CHECK(testutil::waitFor([&]() {
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
            CHECK(deviceItems == 0);

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
                signAuthorship(saved, aliceIdentity, /*withCert=*/false);
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({"saved-echo", "device",
                    sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({saved}))),
                        alice->ownEpochs().front())});
            }
            bool sawSaved = false;
            for (const IncomingMessage& item : alice->sync()) {
                if (item.fromFingerprint == alice->fingerprint() && item.text == "note to self") {
                    sawSaved = true;
                    CHECK(item.sentByUs);
                    CHECK(item.fromDevice == aliceIdentity.device());
                }
            }
            CHECK(sawSaved);

            const fs::path tooBig = scratch / "bz-pass-saved-big.bin";
            std::ofstream(tooBig, std::ios::binary) << std::string(kMaxMediaBytes + 1, 'b');
            CHECK_THROWS(alice->sendFile(alice->fingerprint(), tooBig.string(), "", {}, ""));
            fs::remove(tooBig);

            const fs::path note = scratch / "bz-pass-saved-note.txt";
            std::ofstream(note, std::ios::binary) << "kept with the message";
            const std::string noteId = "00112233445566778899aabbccddeeff";
            alice->sendFile(alice->fingerprint(), note.string(), noteId);
            fs::remove(note);
            const std::optional<Bytes> kept = alice->fileBytes(noteId);
            CHECK(kept.has_value());
            CHECK(std::string(kept->begin(), kept->end()) == "kept with the message");
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

            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.refusePassRegistration = true;
            }
            CHECK_THROWS(alice->setBlocked(bob->fingerprint(), false));
            CHECK(alice->isBlocked(bob->fingerprint()));
            CHECK(held() == 0);
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.refusePassRegistration = false;
            }

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
                    {"STORAGE_FULL", "CONTACT_RATE_LIMITED", "DELIVERY_REJECTED"}) {
                    refuseOnce(code);
                    alice->sync();
                    CHECK(alice->canWriteTo(bob->fingerprint()));
                }
                alice->sendMessage(bob->fingerprint(), "and this one goes");
            }

            bob->sendMessage(alice->fingerprint(), "after the unblock");
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : alice->sync()) {
                    if (item.text == "after the unblock") {
                        return true;
                    }
                }
                return false;
            }));
        }

        {
            const DeviceCredential bobIdentity = deviceOf(bDir);
            const std::int64_t invitedAt = nowMillis();
            nlohmann::json invite = {{"v", 1}, {"type", "call.invite"}, {"id", "declined-call"},
                {"from", bob->fingerprint()}, {"sentAt", invitedAt}, {"callId", "declined-call-id"},
                {"dest", std::string(kB33LabelChars, 'm') + ".b32.i2p"},
                {"key", toBase64(randomBytes(kAeadKeyBytes))}};
            signAuthorship(invite, bobIdentity, /*withCert=*/false);
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({"declined-call", "content",
                    sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({invite}))),
                        alice->ownEpochs().front())});
            }
            (void)alice->sync();
            CHECK(alice->currentCall().state == Session::CallState::eIncoming);
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.refuseWith = "STORAGE_FULL";
            }
            std::mutex outcomeMutex;
            std::optional<DeliveryOutcome> declined;
            DeliveryWatch watch;
            watch.onOutcome = [&](const DeliveryOutcome& outcome) {
                const std::lock_guard<std::mutex> lock(outcomeMutex);
                declined = outcome;
            };
            alice->declineCall("declined-call-id", watch);
            CHECK(alice->currentCall().state == Session::CallState::eIdle);
            CHECK(testutil::waitFor([&]() {
                const std::lock_guard<std::mutex> lock(outcomeMutex);
                return declined.has_value();
            }));
            CHECK(!declined->stored);
            CHECK(declined->errorCode == "STORAGE_FULL");
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.refuseWith.clear();
            }
            const std::vector<Session::CompletedCall> logged = alice->takeCallLog();
            CHECK(logged.size() == 1);
            CHECK(logged[0].record.has_value());
            const IncomingMessage& record = *logged[0].record;
            CHECK(record.contentType == kTypeCallRecord);
            CHECK(record.text == kCallMarkDeclined);
            CHECK(record.callIncoming);
            CHECK(record.sentByUs);
            CHECK(record.fromFingerprint == bob->fingerprint());
            CHECK(record.sentAt == invitedAt);
            CHECK(record.e2eId.size() == 2 * kMessageIdBytes);

            nlohmann::json forgedRecord = {{"v", 1}, {"type", kTypeCallRecord}, {"id", record.e2eId},
                {"from", bob->fingerprint()}, {"sentAt", invitedAt}, {"callId", "declined-call-id"},
                {"outcome", kCallMarkAnswered}};
            signAuthorship(forgedRecord, bobIdentity, /*withCert=*/false);
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({"forged-record", "content",
                    sealToEpoch(
                        padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({forgedRecord}))),
                        alice->ownEpochs().front())});
            }
            for (const IncomingMessage& item : alice->sync()) {
                CHECK(item.contentType != kTypeCallRecord);
            }
        }

        {
            const DeviceCredential bobIdentity = deviceOf(bDir);
            const std::string strangerFingerprint = Identity::generate().fingerprint();
            const auto intoAliceMailbox = [&](const std::string& id, nlohmann::json content) {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({id, "content",
                    sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({content}))),
                        alice->ownEpochs().front())});
            };
            const auto text = [](const std::string& from, const std::string& id,
                                  const std::string& body) {
                return nlohmann::json{{"v", 1}, {"type", "text"}, {"id", id}, {"from", from},
                    {"sentAt", 1}, {"text", body}};
            };

            nlohmann::json forged = text(strangerFingerprint, "forged-1", "trust me, I am them");
            signAuthorship(forged, bobIdentity, /*withCert=*/true);
            intoAliceMailbox("forged-1", forged);
            intoAliceMailbox("unsigned-1", text(bob->fingerprint(), "unsigned-1", "no signature"));
            nlohmann::json honest = text(bob->fingerprint(), "honest-1", "this one is mine");
            signAuthorship(honest, bobIdentity, /*withCert=*/false);
            intoAliceMailbox("honest-1", honest);
            nlohmann::json forgedInBatch = text(strangerFingerprint, "forged-2", "slipped in first");
            signAuthorship(forgedInBatch, bobIdentity, /*withCert=*/true);
            nlohmann::json honestInBatch = text(bob->fingerprint(), "honest-2", "after a forged one");
            signAuthorship(honestInBatch, bobIdentity, /*withCert=*/false);
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({"mixed-1", "content",
                    sealToEpoch(padToLadder(nlohmann::json::to_cbor(
                                     nlohmann::json::array({forgedInBatch, honestInBatch}))),
                        alice->ownEpochs().front())});
            }

            const std::string plantedPeer = Identity::generate().fingerprint();
            const auto deviceNotice = [&](const std::string& id, nlohmann::json extra) {
                extra["v"] = 1;
                extra["id"] = id;
                extra["from"] = bob->fingerprint();
                extra["sentAt"] = 1;
                extra["device"] = "not-a-device-of-hers";
                signAuthorship(extra, bobIdentity, /*withCert=*/false);
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
                                     {"dest", "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p"},
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
            const fs::path cDir = scratch / "bz-pass-c";
            fs::remove(cDir);
            const std::unique_ptr<Session> carol = Session::create(cDir, AccountKind::eUser, endpoint, std::string{});
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[carol->fingerprint()]
                    = "flkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";
            }
            carol->registerAccount();
            carol->setFetchTransport(directDial);
            carol->setOutboundLinks(courierFor());

            const std::string longestName(kMaxAccountNameBytes, 'n');
            alice->setDisplayName(longestName);
            CHECK(alice->displayName() == longestName);
            const std::string longestGreeting(kMaxContactGreetingBytes, 'g');
            addByInvite(*alice, carol->inviteUri(), longestGreeting);

            const std::size_t largest = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.largestContactRequest;
            }();
            std::printf("TestDeliveryPass: the largest contact request is %zu bytes\n", largest);
            CHECK(largest <= kMaxContactRequestBytes);
            CHECK(kMaxContactRequestBytes - largest < 64);
        }

        {
            const fs::path fDir = scratch / "bz-pass-heaviest";
            fs::remove(fDir);
            const std::unique_ptr<Session> fiona
                = Session::create(fDir, AccountKind::eUser, endpoint, std::string{});
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[fiona->fingerprint()]
                    = "ilkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";
            }
            fiona->registerAccount();
            fiona->setFetchTransport(directDial);
            fiona->setOutboundLinks(courierFor());
            addByInvite(*alice, fiona->inviteUri(), "the heaviest picture");
            CHECK(testutil::waitFor([&]() {
                fiona->sync();
                return fiona->contactIsPending(alice->fingerprint());
            }));
            const auto heldForAlice = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice->fingerprint()].size();
            };
            const std::size_t before = heldForAlice();
            fiona->sendPicture(alice->fingerprint(), Bytes(kMaxPictureBytes, 0x7b),
                std::string(kMaxMediaNameBytes, 'n'), std::string(kMaxMediaMimeBytes, 'm'), {}, {},
                std::string(kMaxMessageIdBytes, 'r'), true);
            CHECK(testutil::waitFor([&]() { return heldForAlice() > before; }));
            const std::size_t heaviest = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice->fingerprint()].back().payload.size();
            }();
            std::printf("TestDeliveryPass: the heaviest picture message is %zu bytes\n", heaviest);
            constexpr std::size_t kKnownIdBytes = 1 + kDeviceIdLength;
            constexpr std::size_t kHeaviestSlackBytes = 64 + (kMaxKnownDevices - 1) * kKnownIdBytes;
            CHECK(heaviest <= kMaxMessagePayloadBytes);
            CHECK(kMaxMessagePayloadBytes - heaviest < kHeaviestSlackBytes);
            const std::size_t beforeFile = heldForAlice();
            fiona->sendFileBytes(alice->fingerprint(), std::string(kMaxMediaNameBytes, 'f'),
                Bytes(kMaxMediaBytes, 0x7c), {}, {}, std::string(kMaxMessageIdBytes, 'r'), true);
            CHECK(testutil::waitFor([&]() { return heldForAlice() > beforeFile; }));
            const std::size_t heaviestFile = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice->fingerprint()].back().payload.size();
            }();
            std::printf("TestDeliveryPass: the heaviest file message is %zu bytes\n", heaviestFile);
            CHECK(heaviestFile <= kMaxMessagePayloadBytes);
            CHECK_THROWS(fiona->sendFileBytes(
                alice->fingerprint(), "over.txt", Bytes(kMaxMediaBytes + 1, 1)));
            CHECK_THROWS(fiona->sendPicture(alice->fingerprint(), Bytes(kMaxPictureBytes + 1, 1),
                "over.png", "image/png"));
            CHECK_THROWS(fiona->sendPicture(alice->fingerprint(), Bytes{1},
                std::string(kMaxMediaNameBytes + 1, 'n'), "image/png"));
            CHECK_THROWS(fiona->sendMessage(alice->fingerprint(), "long reply", {}, {},
                std::string(kMaxMessageIdBytes + 1, 'r')));
        }

        {
            const fs::path dDir = scratch / "bz-pass-d";
            fs::remove(dDir);
            const std::unique_ptr<Session> dana = Session::create(dDir, AccountKind::eUser, endpoint, std::string{});
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[dana->fingerprint()]
                    = "glkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";
            }
            dana->registerAccount();
            dana->setFetchTransport(directDial);
            dana->setOutboundLinks(courierFor());

            const auto heldForAlice = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[alice->fingerprint()].size();
            };
            const std::size_t beforeAdding = heldForAlice();
            addByInvite(*alice, dana->inviteUri(), "let me in");
            bool askedTwice = true;
            try {
                addByInvite(*alice, dana->inviteUri(), "let me in again");
            } catch (const std::exception&) {
                askedTwice = false;
            }
            CHECK(!askedTwice);
            const std::size_t beforeRequests = heldForAlice();
            CHECK(beforeRequests == beforeAdding);
            CHECK(alice->hasContact(dana->fingerprint()));
            CHECK(testutil::waitFor([&]() {
                dana->sync();
                return dana->contactIsPending(alice->fingerprint());
            }));
            CHECK(dana->hasContact(alice->fingerprint()));
            CHECK(dana->contactIsPending(alice->fingerprint()));
            CHECK(heldForAlice() == beforeRequests);

            dana->sendReceipt(alice->fingerprint(), "whatever-they-sent");
            CHECK(heldForAlice() == beforeRequests);

            const auto courierNews = std::make_shared<std::atomic<int>>(0);
            dana->onCourierNews([courierNews]() { ++*courierNews; });
            dana->acceptContactRequest(alice->fingerprint());
            CHECK(dana->contactIsPending(alice->fingerprint()));
            CHECK(dana->contactAcceptInFlight(alice->fingerprint()));
            dana->acceptContactRequest(alice->fingerprint());
            CHECK(testutil::waitFor([&]() {
                if (courierNews->load() == 0) {
                    return false;
                }
                dana->flushPendingEchoes();
                return !dana->contactAcceptInFlight(alice->fingerprint());
            }));
            CHECK(!dana->contactIsPending(alice->fingerprint()));
            CHECK(testutil::waitFor([&]() { return heldForAlice() > beforeRequests; }));
            CHECK(testutil::waitFor([&]() {
                dana->sync();
                return !dana->contactIsPending(alice->fingerprint());
            }));
            CHECK(!dana->contactIsPending(alice->fingerprint()));
            CHECK(!dana->contactAcceptInFlight(alice->fingerprint()));

            alice->removeContact(dana->fingerprint());
            CHECK(!alice->hasContact(dana->fingerprint()));
            const std::size_t beforeReturn = heldForAlice();
            addByInvite(*alice, dana->inviteUri(), "me again");
            CHECK(testutil::waitFor([&]() {
                dana->sync();
                return dana->contactAcceptInFlight(alice->fingerprint());
            }));
            CHECK(testutil::waitFor([&]() { return heldForAlice() > beforeReturn; }));
            CHECK(testutil::waitFor([&]() {
                dana->sync();
                return !dana->contactIsPending(alice->fingerprint());
            }));
            CHECK(!dana->contactIsPending(alice->fingerprint()));
            CHECK(testutil::waitFor([&]() {
                alice->sync();
                return alice->canWriteTo(dana->fingerprint());
            }));
        }

        {
            const fs::path eDir = scratch / "bz-pass-e";
            fs::remove(eDir);
            const std::unique_ptr<Session> erin = Session::create(eDir, AccountKind::eUser, endpoint, std::string{});
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[erin->fingerprint()]
                    = "hlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";
            }
            erin->registerAccount();
            erin->setFetchTransport(directDial);
            erin->setOutboundLinks(courierFor());

            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.refuseWith = "CONTACT_RATE_LIMITED";
            }
            CHECK_THROWS(addByInvite(*alice, erin->inviteUri(), "refused"));
            CHECK(!alice->hasContact(erin->fingerprint()));
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.refuseWith.clear();
            }

            const std::string erinDest = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.destFor[erin->fingerprint()];
            }();
            const std::string aliceDest = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.destFor[alice->fingerprint()];
            }();
            const auto contactRequestsFor = [&](const std::string& fingerprint) {
                const std::lock_guard<std::mutex> lock(m.mu);
                return std::count_if(m.mailbox[fingerprint].begin(), m.mailbox[fingerprint].end(),
                    [](const Mock::Item& item) { return item.cls == kContactDeliveryClass; });
            };
            constexpr std::chrono::seconds kQuickDial{1};
            constexpr std::chrono::seconds kQuickReply{1};
            constexpr std::chrono::seconds kQuickBound{3};
            constexpr std::chrono::milliseconds kStillWaiting{3000};
            constexpr std::int64_t kOldPublished = 1000;
            constexpr std::int64_t kLeaseSeconds = 600;

            std::atomic<bool> erinDown{true};
            OutboundCourier::Links towardsErin = courierFor();
            towardsErin.openStream = [&](const std::string& toDest,
                                         std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                if (toDest == erinDest && erinDown.load()) {
                    return nullptr;
                }
                return std::make_shared<MockServerStream>(m, ackSigning);
            };
            alice->setOutboundLinks(towardsErin);
            Session::ContactCardRequest asking;
            asking.uriOrAlias = erin->inviteUri();
            asking.introText = "are you there";
            asking.requestId = "first-request";
            const Session::ContactCardResolved resolvedErin = Session::resolveContactCard(
                alice->contactFetchContext(), asking, [](Session::CardStep) {});
            CHECK(resolvedErin.ok);
            std::mutex settledMutex;
            std::vector<OutboundCourier::Outcome> requestOutcomes;
            DeliveryWatch requestWatch;
            requestWatch.onOutcome = [&](const OutboundCourier::Outcome& outcome) {
                const std::lock_guard<std::mutex> lock(settledMutex);
                requestOutcomes.push_back(outcome);
            };
            const auto requestsSettled = [&]() {
                const std::lock_guard<std::mutex> lock(settledMutex);
                return requestOutcomes.size();
            };
            alice->commitContactAdd(resolvedErin, requestWatch);
            CHECK(!testutil::waitFor([&]() { return requestsSettled() > 0; }, kStillWaiting));
            CHECK(alice->contactAwaitsAnswer(erin->fingerprint()));
            alice->sendContactRequest(
                erin->fingerprint(), "second-request", "are you there", requestWatch);
            CHECK(contactRequestsFor(erin->fingerprint()) == 0);
            MailWaitGate aliceWait;
            alice->openOutboxWhenAnswered(aliceWait);
            erinDown = false;
            i2p::networkChanged();
            CHECK(!testutil::waitFor([&]() { return requestsSettled() > 0; }, kStillWaiting));
            aliceWait.answered();
            CHECK(testutil::waitFor([&]() { return requestsSettled() == 2; }));
            {
                const std::lock_guard<std::mutex> lock(settledMutex);
                CHECK(requestOutcomes.at(0).stored && requestOutcomes.at(1).stored);
            }
            CHECK(contactRequestsFor(erin->fingerprint()) == 1);
            CHECK(testutil::waitFor([&]() {
                erin->sync();
                return erin->hasContact(alice->fingerprint());
            }));
            CHECK(erin->contactIsPending(alice->fingerprint()));
            std::printf("TestDeliveryPass: a contact request to an unreachable server went once"
                        " the link came back, with no second request\n");

            std::atomic<bool> aliceRestarted{false};
            std::atomic<int> silences{0};
            OutboundCourier::Links towardsAlice = courierFor();
            towardsAlice.openStream = [&](const std::string& toDest,
                                          std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                if (toDest == aliceDest && !aliceRestarted.load()) {
                    ++silences;
                    return std::make_shared<SilentServerStream>();
                }
                return std::make_shared<MockServerStream>(m, ackSigning);
            };
            towardsAlice.lookup
                = [&](const std::string&) -> std::optional<i2p::LeaseSetRefresh> {
                i2p::LeaseSetRefresh refresh;
                refresh.before = i2p::LeaseSetSeen{kOldPublished, kOldPublished + kLeaseSeconds};
                refresh.after = refresh.before;
                return refresh;
            };
            CourierTimings quick;
            quick.dial = kQuickDial;
            quick.reply = kQuickReply;
            quick.staleBound = kQuickBound;
            erin->setOutboundLinks(towardsAlice, quick);
            const auto aliceRequestsBefore = contactRequestsFor(alice->fingerprint());
            erin->acceptContactRequest(alice->fingerprint());
            CHECK(erin->contactAcceptInFlight(alice->fingerprint()));
            CHECK(testutil::waitFor([&]() { return silences.load() == 1; }));
            CHECK(!testutil::waitFor([&]() {
                erin->sync();
                return !erin->contactIsPending(alice->fingerprint());
            }, std::chrono::milliseconds(kQuickBound) / 2));
            CHECK(erin->contactAcceptInFlight(alice->fingerprint()));
            aliceRestarted = true;
            CHECK(testutil::waitFor([&]() {
                erin->sync();
                return !erin->contactIsPending(alice->fingerprint());
            }));
            CHECK(!erin->contactAcceptInFlight(alice->fingerprint()));
            CHECK(silences.load() == 1);
            CHECK(testutil::waitFor([&]() {
                alice->sync();
                return alice->canWriteTo(erin->fingerprint());
            }));
            CHECK(!alice->contactAwaitsAnswer(erin->fingerprint()));
            CHECK(erin->canWriteTo(alice->fingerprint()));
            CHECK(contactRequestsFor(alice->fingerprint()) == aliceRequestsBefore);
            std::printf("TestDeliveryPass: an acceptance that met a dead lease set landed by itself"
                        " once that lease set had expired; both sides are contacts\n");
            alice->setOutboundLinks(courierFor());
            erin->setOutboundLinks(courierFor());
        }

        {
            const auto heldFor = [&](const std::string& fingerprint) {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[fingerprint].size();
            };
            const std::string id = "once-only";
            const std::string deliveryId = alice->deliveryIdFor(id, bob->fingerprint());
            const std::size_t before = heldFor(bob->fingerprint());
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.loseReplyTo = deliveryId;
            }
            std::mutex outcomeMutex;
            std::optional<OutboundCourier::Outcome> told;
            DeliveryWatch watch;
            watch.onOutcome = [&](const OutboundCourier::Outcome& outcome) {
                const std::lock_guard<std::mutex> lock(outcomeMutex);
                told = outcome;
            };
            alice->sendMessage(bob->fingerprint(), "delivered once", id, watch);
            CHECK(testutil::waitFor([&]() {
                const std::lock_guard<std::mutex> lock(outcomeMutex);
                return told.has_value();
            }));
            {
                const std::lock_guard<std::mutex> lock(outcomeMutex);
                CHECK(told->stored);
            }
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                CHECK(m.offers[deliveryId] == 2);
            }
            CHECK(heldFor(bob->fingerprint()) == before + 1);
            int seen = 0;
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    seen += item.text == "delivered once" ? 1 : 0;
                }
                return seen > 0;
            }));
            for (const IncomingMessage& item : bob->sync()) {
                seen += item.text == "delivered once" ? 1 : 0;
            }
            CHECK(seen == 1);
            std::printf("TestDeliveryPass: a delivery whose reply was lost on an answered stream"
                        " went again at once and was stored once\n");
        }

        {
            const fs::path ritaDir = scratch / "bz-pass-rita";
            const fs::path samDir = scratch / "bz-pass-sam";
            fs::remove(ritaDir);
            fs::remove(samDir);
            std::unique_ptr<Session> rita
                = Session::create(ritaDir, AccountKind::eUser, endpoint, std::string{});
            const std::unique_ptr<Session> sam
                = Session::create(samDir, AccountKind::eUser, endpoint, std::string{});
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[rita->fingerprint()]
                    = "rlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";
                m.destFor[sam->fingerprint()]
                    = "slkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";
            }
            for (Session* const each : {rita.get(), sam.get()}) {
                each->registerAccount();
                each->setFetchTransport(directDial);
                each->setOutboundLinks(courierFor());
            }
            addByInvite(*rita, sam->inviteUri(), "a restart is coming");
            CHECK(testutil::waitFor([&]() {
                sam->sync();
                return sam->contactIsPending(rita->fingerprint());
            }));
            sam->acceptContactRequest(rita->fingerprint());
            CHECK(testutil::waitFor([&]() {
                rita->sync();
                sam->sync();
                return rita->canWriteTo(sam->fingerprint()) && sam->canWriteTo(rita->fingerprint());
            }));
            const std::string samDest = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.destFor[sam->fingerprint()];
            }();
            const auto heldForSam = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[sam->fingerprint()].size();
            };
            CHECK(testutil::waitFor([&]() {
                sam->sync();
                return heldForSam() == 0;
            }));
            OutboundCourier::Links samAway = courierFor();
            samAway.openStream = [&](const std::string& toDest,
                                     std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                if (toDest == samDest) {
                    return nullptr;
                }
                return std::make_shared<MockServerStream>(m, ackSigning);
            };
            rita->setOutboundLinks(samAway);
            const std::string keptId = "kept-across-a-restart";
            rita->sendMessage(sam->fingerprint(), "kept across a restart", keptId);
            const std::string keyboardId = "a-keyboard-across-a-restart";
            rita->sendInteractive(sam->fingerprint(), "pick one after a restart",
                InlineKeyboard{{{"Yes", "yes", {}}}}, keyboardId);
            rita->sendReceipt(sam->fingerprint(), "a-read-message");
            CHECK(!testutil::waitFor([&]() { return heldForSam() > 0; },
                std::chrono::milliseconds(2000)));
            CHECK(!rita->watchDelivery(sam->fingerprint(), "never-sent", DeliveryWatch{}));
            rita.reset();

            rita = Session::open(ritaDir, std::string{});
            CHECK(rita->watchDelivery(sam->fingerprint(), keyboardId, DeliveryWatch{}));
            rita->setFetchTransport(directDial);
            rita->setOutboundLinks(courierFor());
            std::mutex outcomeMutex;
            std::optional<OutboundCourier::Outcome> told;
            DeliveryWatch watch;
            watch.onOutcome = [&](const OutboundCourier::Outcome& outcome) {
                const std::lock_guard<std::mutex> lock(outcomeMutex);
                told = outcome;
            };
            CHECK(rita->watchDelivery(sam->fingerprint(), keptId, watch));
            rita->flushPendingEchoes();
            CHECK(testutil::waitFor([&]() {
                const std::lock_guard<std::mutex> lock(outcomeMutex);
                return told.has_value();
            }));
            {
                const std::lock_guard<std::mutex> lock(outcomeMutex);
                CHECK(told->stored);
            }
            bool sawText = false;
            bool sawReceipt = false;
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : sam->sync()) {
                    sawText = sawText || item.text == "kept across a restart";
                    sawReceipt = sawReceipt
                        || (item.contentType == "receipt" && item.refId == "a-read-message");
                }
                return sawText && sawReceipt;
            }));
            CHECK(testutil::waitFor([&]() {
                rita->flushPendingEchoes();
                return !rita->watchDelivery(sam->fingerprint(), keptId, DeliveryWatch{});
            }));
            std::printf("TestDeliveryPass: a message and a receipt to an unreachable recipient"
                        " outlived closing the account and went once it was back\n");

            std::atomic<int> dialsToSam{0};
            OutboundCourier::Links samGone = courierFor();
            samGone.openStream = [&](const std::string& toDest,
                                     std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                if (toDest == samDest) {
                    ++dialsToSam;
                    return nullptr;
                }
                return std::make_shared<MockServerStream>(m, ackSigning);
            };
            rita->setOutboundLinks(samGone);
            const std::string goneId = "withdrawn-before-it-left";
            const std::string goneText = "never to arrive " + toHex(randomBytes(8));
            rita->sendMessage(sam->fingerprint(), goneText, goneId);
            CHECK(testutil::waitFor([&]() { return dialsToSam.load() > 0; }));
            CHECK(!testutil::waitFor([&]() { return dialsToSam.load() > 1; },
                std::chrono::milliseconds(300)));
            CHECK(testutil::filesHold(ritaDir, accountkey::keyFor(ritaDir, std::string{}), goneText));
            rita->sendDelete(sam->fingerprint(), goneId);
            CHECK(!rita->watchDelivery(sam->fingerprint(), goneId, DeliveryWatch{}));
            CHECK(!testutil::filesHold(ritaDir, accountkey::keyFor(ritaDir, std::string{}), goneText));
            rita->setOutboundLinks(courierFor());
            rita->flushPendingEchoes();
            CHECK(!testutil::waitFor([&]() {
                for (const IncomingMessage& item : sam->sync()) {
                    if (item.text == goneText || item.refId == goneId) {
                        return true;
                    }
                }
                return false;
            }, std::chrono::milliseconds(3000)));
            std::printf("TestDeliveryPass: a message deleted before it left was withdrawn, and"
                        " neither it nor a delete reached the recipient\n");

            dialsToSam = 0;
            rita->setOutboundLinks(samGone);
            const std::string editedId = "edited-before-it-left";
            const std::string firstWords = "words to be taken back " + toHex(randomBytes(8));
            const std::string lastWords = "the words that stand " + toHex(randomBytes(8));
            rita->sendMessage(sam->fingerprint(), firstWords, editedId);
            CHECK(testutil::waitFor([&]() { return dialsToSam.load() > 0; }));
            CHECK(!testutil::waitFor([&]() { return dialsToSam.load() > 1; },
                std::chrono::milliseconds(300)));
            CHECK(testutil::filesHold(ritaDir, accountkey::keyFor(ritaDir, std::string{}), firstWords));
            rita->sendEdit(sam->fingerprint(), editedId, lastWords);
            CHECK(rita->watchDelivery(sam->fingerprint(), editedId, DeliveryWatch{}));
            CHECK(!testutil::filesHold(ritaDir, accountkey::keyFor(ritaDir, std::string{}), firstWords));
            rita->setOutboundLinks(courierFor());
            rita->flushPendingEchoes();
            std::vector<IncomingMessage> arrived;
            CHECK(testutil::waitFor([&]() {
                for (IncomingMessage& item : sam->sync()) {
                    arrived.push_back(std::move(item));
                }
                for (const IncomingMessage& item : arrived) {
                    if (item.e2eId == editedId) {
                        return true;
                    }
                }
                return false;
            }));
            CHECK(!testutil::waitFor([&]() {
                for (IncomingMessage& item : sam->sync()) {
                    arrived.push_back(std::move(item));
                }
                return false;
            }, std::chrono::milliseconds(2000)));
            int copies = 0;
            for (const IncomingMessage& item : arrived) {
                CHECK(item.text != firstWords);
                CHECK(item.refId != editedId);
                if (item.e2eId == editedId) {
                    CHECK(item.text == lastWords);
                    ++copies;
                }
            }
            CHECK(copies == 1);
            std::printf("TestDeliveryPass: a message edited before it left went once, with the"
                        " edited words only\n");
        }

        {
            const Bytes face = {0xFF, 0xD8, 0xFF, 0xE0, 'b', 'o', 'b'};
            bob->setAvatar(face, "image/jpeg");
            CHECK(testutil::waitFor([&]() {
                alice->sync();
                return !alice->contactAvatar(bob->fingerprint()).empty();
            }));
            CHECK(alice->contactAvatar(bob->fingerprint()) == face);
            const std::string bobStatus = "Bob's status";
            bob->setStatus(bobStatus);
            CHECK(testutil::waitFor([&]() {
                alice->sync();
                return alice->contactStatus(bob->fingerprint()) == bobStatus;
            }));
            alice->renameContact(bob->fingerprint(), "Bob of the book");

            const fs::path secondDir = scratch / "second.db";
            fs::remove(secondDir);
            Session::importAccount(earlyBundle, secondDir, "bundle-password");
            const std::unique_ptr<Session> second = Session::open(secondDir, std::string{});
            CHECK(second->fingerprint() == alice->fingerprint());
            CHECK(!second->hasContact(bob->fingerprint()));

            second->setFetchTransport(directDial);
            second->setOutboundLinks(courierFor());
            second->registerAccount();
            second->sync();
            CHECK(testutil::waitFor([&]() {
                second->flushPendingEchoes();
                return selfHolds("device.contacts-request");
            }));
            alice->sync();
            CHECK(testutil::waitFor([&]() {
                second->sync();
                return second->hasContact(bob->fingerprint());
            }));
            CHECK(second->hasContact(bob->fingerprint()));
            CHECK(second->contactDisplayName(bob->fingerprint()) == "Bob of the book");
            CHECK(second->contactAvatar(bob->fingerprint()) == face);
            CHECK(second->contactStatus(bob->fingerprint()) == bobStatus);
            CHECK(second->canWriteTo(bob->fingerprint()));
            alice->publishRouting();
            CHECK(testutil::waitFor([&]() {
                second->sync();
                return second->hasI2pDestination();
            }));
            CHECK(second->i2pAddress() == alice->i2pAddress());
            CHECK(second->addressKeys().sealingPem == alice->addressKeys().sealingPem);
            CHECK(second->addressKeys().signingPem == alice->addressKeys().signingPem);
            alice->issueAddressKeys();
            alice->publishRouting();
            CHECK(testutil::waitFor([&]() {
                second->sync();
                return second->addressKeys().sealingPem == alice->addressKeys().sealingPem;
            }));
            CHECK(second->addressKeys().signingPem == alice->addressKeys().signingPem);
            CHECK(testutil::waitFor([&]() {
                alice->flushPendingEchoes();
                return alice->routingFanout().contacts.empty();
            }));
            bool bobHeardKeys = false;
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    bobHeardKeys = bobHeardKeys || item.contentType == kTypeAccountCard;
                }
                return bobHeardKeys;
            }));
            bob->sendMessage(alice->fingerprint(), "hello, second device");
            bool sawBob = false;
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : second->sync()) {
                    sawBob = sawBob || item.text == "hello, second device";
                }
                return sawBob;
            }));
            CHECK(sawBob);

            {
                const fs::path fDir = scratch / "bz-pass-f";
                fs::remove(fDir);
                const std::unique_ptr<Session> finn = Session::create(fDir, AccountKind::eUser, endpoint, std::string{});
                {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    m.destFor[finn->fingerprint()]
                        = "hlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";
                }
                finn->registerAccount();
                finn->setFetchTransport(directDial);
                finn->setOutboundLinks(courierFor());

                addByInvite(*alice, finn->inviteUri(), "added on one device");
                alice->renameContact(finn->fingerprint(), "Finn of the phone");
                CHECK(testutil::waitFor([&]() {
                    second->sync();
                    return second->hasContact(finn->fingerprint());
                }));
                CHECK(second->hasContact(finn->fingerprint()));
                CHECK(testutil::waitFor([&]() {
                    finn->sync();
                    return finn->contactIsPending(alice->fingerprint());
                }));
                finn->acceptContactRequest(alice->fingerprint());
                finn->sendMessage(alice->fingerprint(), "seen on the other device too");
                bool sawFinn = false;
                CHECK(testutil::waitFor([&]() {
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
                CHECK(testutil::waitFor([&]() {
                    alice->sync();
                    return alice->contactAvatar(bob->fingerprint()) == huge;
                }));
                CHECK(alice->contactAvatar(bob->fingerprint()) == huge);

                const fs::path thirdDir = scratch / "third.db";
                fs::remove(thirdDir);
                Session::importAccount(earlyBundle, thirdDir, "bundle-password");
                const std::unique_ptr<Session> third = Session::open(thirdDir, std::string{});
                third->setFetchTransport(directDial);
                third->setOutboundLinks(courierFor());
                third->registerAccount();
                third->sync();
                CHECK(testutil::waitFor([&]() {
                    third->flushPendingEchoes();
                    return selfHolds("device.contacts-request");
                }));
                alice->sync();
                CHECK(testutil::waitFor([&]() {
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
            const fs::path laterBundle = scratch / "bz-pass-later.bundle";
            fs::remove(laterBundle);
            alice->exportAccount(laterBundle, "bundle-password");
            CHECK(alice->canWriteTo(bob->fingerprint()));

            const fs::path fourthDir = scratch / "fourth.db";
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
                signAuthorship(notice, aliceIdentity, /*withCert=*/false);
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({"self-" + notice.at("id").get<std::string>()
                        + "-" + std::to_string(m.nextId++),
                    "device",
                    sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({notice}))),
                        alice->ownEpochs().front())});
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
                    sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({inner}))),
                        alice->ownEpochs().front())});
            }
            for (const IncomingMessage& item : alice->sync()) {
                CHECK(item.fromFingerprint != stranger);
            }
            CHECK(!alice->hasContact(stranger));
        }

        {
            const devicetest::Account sneakAccount;
            const DeviceCredential& sneak = sneakAccount.device;
            const nlohmann::json bootstrap = {{"kind", "user"},
                {"epochs",
                    epochsJson({{epochAt(nowSeconds()), kFirstEpochGeneration, sneak.device(), Key::generateSealing().publicDer()}})},
                {"dest", std::string(56, 'q') + ".b32.i2p"},
                {"servingKey", toBase64(Key::generateSealing().publicDer())},
                {"pass", toBase64(randomBytes(kSneakPassBytes))}};
            nlohmann::json request = {{"v", 1}, {"type", "contact.request"}, {"id", "sneak-request"},
                {"from", sneak.account()}, {"sentAt", 1}, {"text", "hello"}, {"dn", "Sneak"},
                {"bootstrap", bootstrap}};
            signAuthorship(request, sneak, /*withCert=*/true);
            nlohmann::json invite = {{"v", 1}, {"type", "call.invite"}, {"id", "sneak-call"},
                {"from", sneak.account()}, {"sentAt", 1}, {"callId", "sneak-call-id"}};
            signAuthorship(invite, sneak, /*withCert=*/false);
            const auto deliver = [&](const std::string& id, const std::string& cls,
                                     const std::vector<nlohmann::json>& items) {
                std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[alice->fingerprint()].push_back({id, cls,
                    sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json(items))),
                        alice->ownEpochs().front())});
            };
            const auto fromSneak = [&]() {
                std::size_t count = 0;
                for (const IncomingMessage& item : alice->sync()) {
                    count += item.fromFingerprint == sneak.account() ? 1 : 0;
                }
                return count;
            };

            deliver("sneak-both", kContactDeliveryClass, {request, invite});
            CHECK(fromSneak() == 0);
            CHECK(!alice->hasContact(sneak.account()));

            deliver("sneak-asks", kContactDeliveryClass, {request});
            CHECK(fromSneak() == 1);
            CHECK(alice->contactIsPending(sneak.account()));
            deliver("sneak-rings", "content", {invite});
            CHECK(fromSneak() == 0);
            CHECK(alice->currentCall().state == Session::CallState::eIdle);
            CHECK(alice->contactIsPending(sneak.account()));
            alice->removeContact(sneak.account());
        }

        {
            {
                std::lock_guard<std::mutex> lock(m.mu);
                m.refuseWith = "STORAGE_FULL";
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
            CHECK(testutil::waitFor([&]() {
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
            const fs::path gDir = scratch / "bz-pass-g";
            fs::remove(gDir);
            std::unique_ptr<Session> gail
                = Session::create(gDir, AccountKind::eUser, endpoint, std::string{});
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.destFor[gail->fingerprint()]
                    = "klkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";
            }
            gail->registerAccount();
            gail->setFetchTransport(directDial);
            gail->setOutboundLinks(courierFor());
            addByInvite(*gail, bob->inviteUri(), "a file for you");
            bob->sync();
            bob->acceptContactRequest(gail->fingerprint());
            CHECK(testutil::waitFor([&]() {
                gail->sync();
                return gail->canWriteTo(bob->fingerprint());
            }));

            const fs::path transfers = gDir.parent_path() / ".transfers";
            const auto servingFiles = [&transfers]() {
                std::set<std::string> names;
                if (!fs::exists(transfers)) {
                    return names;
                }
                for (const fs::directory_entry& entry : fs::directory_iterator(transfers)) {
                    const std::string name = entry.path().filename().string();
                    if (name.starts_with("file-serve-")) {
                        names.insert(name);
                    }
                }
                return names;
            };
            const std::set<std::string> earlier = servingFiles();
            const fs::path offered = scratch / "bz-pass-offered.bin";
            std::ofstream(offered, std::ios::binary)
                << std::string(kMaxMediaBytes + 1, 'o');
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
            CHECK(testutil::waitFor([&]() {
                for (const IncomingMessage& item : bob->sync()) {
                    if (item.contentType == "file"
                        && item.attachmentName == offered.filename().string()) {
                        announced = item;
                    }
                }
                return !announced.e2eId.empty();
            }));
            const FileTarget copy
                = fileTargetAt(scratch / "bz-pass-offered-copy.bin");
            bob->requestFile(gail->fingerprint(), announced.e2eId, announced.attachmentRef, copy);

            const DeviceCredential gailIdentity = deviceOf(gDir);
            FileOffer elsewhere;
            elsewhere.fileId = announced.e2eId;
            elsewhere.host = std::string(56, 'w') + ".b32.i2p";
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
            signAuthorship(unasked, gailIdentity, /*withCert=*/false);
            {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[bob->fingerprint()].push_back({"unasked-offer", "content",
                    sealToEpoch(
                        padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({unasked}))),
                        bob->ownEpochs().front())});
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
                CHECK(!fs::exists(transfers / name));
            }
            bob->setTransferHandler({});
            fs::remove(offered);
            fs::remove(gDir);
        }

        {
            std::atomic<std::int64_t> utc{nowSeconds()};
            const UtcClock clock = [&utc]() { return utc.load(); };
            const auto accountAt = [&](const std::string& name, const AccountKind kind,
                                       const std::string& dest) {
                const fs::path dir = scratch / name;
                fs::remove(dir);
                std::unique_ptr<Session> session = Session::create(dir, kind, endpoint, std::string{});
                {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    m.destFor[session->fingerprint()] = dest;
                }
                session->setPresenceClock(clock);
                session->registerAccount();
                session->setFetchTransport(directDial);
                session->setOutboundLinks(courierFor());
                return session;
            };
            const auto befriend = [&](Session& asking, Session& asked) {
                addByInvite(asking, asked.inviteUri(), "schedules");
                CHECK(testutil::waitFor([&]() {
                    asked.sync();
                    return asked.contactIsPending(asking.fingerprint());
                }));
                asked.acceptContactRequest(asking.fingerprint());
            };
            const auto offer = [&](const DeviceCredential& from, const nlohmann::json& days, Session& to) {
                nlohmann::json inner = {{"v", 1}, {"type", "presence.schedule"},
                    {"id", toHex(randomBytes(kMessageIdBytes))}, {"from", from.account()},
                    {"sentAt", nowMillis()}, {"days", days}};
                signAuthorship(inner, from, /*withCert=*/false);
                {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    m.mailbox[to.fingerprint()].push_back({inner.at("id").get<std::string>(),
                        "content",
                        sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({inner}))),
                        to.ownEpochs().front())});
                }
                for (const IncomingMessage& item : to.sync()) {
                    CHECK(item.contentType != "unsupported");
                }
            };

            const fs::path earlyPam = scratch / "bz-presence-early.bundle";
            std::unique_ptr<Session> pam
                = accountAt("bz-presence-pam", AccountKind::eUser,
                    "plkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p");
            fs::remove(earlyPam);
            pam->exportAccount(earlyPam, "bundle-password");
            std::unique_ptr<Session> quin
                = accountAt("bz-presence-quin", AccountKind::eUser,
                    "qlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p");
            const PresenceDay today = presenceDayOf(utc.load());
            befriend(*pam, *quin);
            const PresenceSchedule pamDays = presenceScheduleFrom(pam->presenceSeed(), today);
            const PresenceSchedule quinDays = presenceScheduleFrom(quin->presenceSeed(), today);
            CHECK(testutil::waitFor([&]() {
                quin->sync();
                pam->sync();
                return pam->contactPresence(quin->fingerprint()) == quinDays
                    && quin->contactPresence(pam->fingerprint()) == pamDays;
            }));

            {
                const fs::path laterPam = scratch / "bz-presence-later.bundle";
                fs::remove(laterPam);
                pam->exportAccount(laterPam, "bundle-password");
                const fs::path restoredDir = scratch / "bz-presence-restored";
                fs::remove(restoredDir);
                Session::importAccount(laterPam, restoredDir, "bundle-password");
                const std::unique_ptr<Session> restored = Session::open(restoredDir, std::string{});
                CHECK(restored->presenceSeed().bytes() == pam->presenceSeed().bytes());
                CHECK(restored->contactPresence(quin->fingerprint()) == quinDays);

                const fs::path twinDir = scratch / "bz-presence-twin";
                fs::remove(twinDir);
                Session::importAccount(earlyPam, twinDir, "bundle-password");
                const std::unique_ptr<Session> twin = Session::open(twinDir, std::string{});
                twin->setPresenceClock(clock);
                CHECK(twin->presenceSeed().bytes() == pam->presenceSeed().bytes());
                CHECK(!twin->hasContact(quin->fingerprint()));
                twin->setFetchTransport(directDial);
                twin->setOutboundLinks(courierFor());
                twin->registerAccount();
                twin->sync();
                CHECK(testutil::waitFor([&]() {
                    twin->flushPendingEchoes();
                    return postedToSelf(scratch / "bz-presence-pam", pam->fingerprint(),
                        "device.contacts-request");
                }));
                pam->sync();
                CHECK(testutil::waitFor([&]() {
                    twin->sync();
                    return twin->contactPresence(quin->fingerprint()) == quinDays;
                }));
            }

            const DeviceCredential quinIdentity = deviceOf(scratch / "bz-presence-quin");
            const PresenceSeed otherSeed = PresenceSeed::generate();
            const auto unchanged = [&]() {
                return pam->contactPresence(quin->fingerprint()) == quinDays;
            };
            offer(devicetest::Account{}.device, presenceScheduleJson(presenceScheduleFrom(otherSeed, today + 1)),
                *pam);
            CHECK(unchanged());
            {
                nlohmann::json gap = presenceScheduleJson(presenceScheduleFrom(otherSeed, today + 1));
                gap.erase(gap.begin() + 1);
                offer(quinIdentity, gap, *pam);
                CHECK(unchanged());
                offer(quinIdentity,
                    presenceScheduleJson(
                        presenceScheduleFrom(otherSeed, today + 1, kPresenceHorizonDays + 1)),
                    *pam);
                CHECK(unchanged());
                nlohmann::json plainHost = presenceScheduleJson(presenceScheduleFrom(otherSeed, today + 1));
                plainHost[0]["dest"] = "qlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
                offer(quinIdentity, plainHost, *pam);
                CHECK(unchanged());
                nlohmann::json shortKey = presenceScheduleJson(presenceScheduleFrom(otherSeed, today + 1));
                shortKey[0]["reader"] = toBase64(randomBytes(kShortReaderBytes));
                offer(quinIdentity, shortKey, *pam);
                CHECK(unchanged());
                offer(quinIdentity, presenceScheduleJson(presenceScheduleFrom(otherSeed, today - 2)),
                    *pam);
                CHECK(unchanged());
                offer(quinIdentity, presenceScheduleJson(presenceScheduleFrom(otherSeed, today - 1)),
                    *pam);
                CHECK(unchanged());
                pam->setBlocked(quin->fingerprint(), true);
                offer(quinIdentity, presenceScheduleJson(presenceScheduleFrom(otherSeed, today + 1)),
                    *pam);
                pam->setBlocked(quin->fingerprint(), false);
                CHECK(unchanged());
            }

            {
                std::unique_ptr<Session> robot = accountAt("bz-presence-bot", AccountKind::eBot,
                    "rlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p");
                befriend(*pam, *robot);
                CHECK(testutil::waitFor([&]() {
                    robot->sync();
                    pam->sync();
                    return pam->canWriteTo(robot->fingerprint());
                }));
                robot->sync();
                pam->sync();
                CHECK(pam->contactPresence(robot->fingerprint()).empty());
                CHECK(robot->contactPresence(pam->fingerprint()).empty());
                const DeviceCredential robotIdentity = deviceOf(scratch / "bz-presence-bot");
                offer(robotIdentity, presenceScheduleJson(presenceScheduleFrom(otherSeed, today)), *pam);
                CHECK(pam->contactPresence(robot->fingerprint()).empty());
                const DeviceCredential pamIdentity = deviceOf(scratch / "bz-presence-pam");
                offer(pamIdentity, presenceScheduleJson(presenceScheduleFrom(otherSeed, today)), *robot);
                CHECK(robot->contactPresence(pam->fingerprint()).empty());

                const auto storedContact = [&](const std::string& account, const std::string& peer) {
                    return nlohmann::json::parse(
                        AccountDb(scratch / account, std::string{}).text("contacts")).at(peer);
                };
                CHECK(!storedContact("bz-presence-bot", pam->fingerprint()).contains("presence"));
                CHECK(!storedContact("bz-presence-pam", robot->fingerprint()).contains("presence"));
                CHECK(storedContact("bz-presence-pam", quin->fingerprint()).contains("presence"));
                const std::string robotFingerprint = robot->fingerprint();
                robot.reset();
                const std::unique_ptr<Session> reopened
                    = Session::open(scratch / "bz-presence-bot", std::string{});
                CHECK(reopened->fingerprint() == robotFingerprint);
                CHECK(reopened->canWriteTo(pam->fingerprint()));
            }

            const PresenceSchedule moved = presenceScheduleFrom(quin->presenceSeed(), today + 1);
            offer(quinIdentity, presenceScheduleJson(moved), *pam);
            CHECK(pam->contactPresence(quin->fingerprint()) == moved);

            const std::int64_t wholeDays = kPresenceHorizonDays - kPresenceRefreshBelowDays - 1;
            utc.store(utc.load() + wholeDays * kSecondsPerDay);
            for (int pass = 0; pass < kQuietPasses; ++pass) {
                pam->sync();
                quin->sync();
            }
            const PresenceSchedule stillHeld = quin->contactPresence(pam->fingerprint());
            CHECK(!stillHeld.empty());
            CHECK(stillHeld.front().day == today + wholeDays);
            CHECK(stillHeld.back().day == pamDays.back().day);

            utc.store(utc.load() + 2 * kSecondsPerDay);
            pam->flushPendingEchoes();
            utc.store(utc.load() + kSecondsPerHour);
            const PresenceSchedule refreshed
                = presenceScheduleFrom(pam->presenceSeed(), presenceDayOf(utc.load()));
            CHECK(testutil::waitFor([&]() {
                pam->sync();
                quin->sync();
                return quin->contactPresence(pam->fingerprint()) == refreshed;
            }));
        }

        {
            std::atomic<std::int64_t> utc{nowSeconds()};
            const UtcClock clock = [&utc]() { return utc.load(); };
            const auto accountAt = [&](const std::string& name, const std::string& dest) {
                const fs::path dir = scratch / name;
                fs::remove(dir);
                std::unique_ptr<Session> session
                    = Session::create(dir, AccountKind::eUser, endpoint, std::string{});
                {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    m.destFor[session->fingerprint()] = dest;
                }
                session->setEpochClock(clock);
                session->registerAccount();
                session->setFetchTransport(directDial);
                session->setOutboundLinks(courierFor());
                return session;
            };
            const auto keysOf = [&](const std::string& name, const EpochNumber n) {
                std::size_t keys = 0;
                for (const nlohmann::json& entry :
                    nlohmann::json::parse(AccountDb(scratch / name, std::string{}).text("epochs"))) {
                    keys += entry.at("n").get<EpochNumber>() == n ? 1 : 0;
                }
                return keys;
            };
            // The mock keeps one mailbox per account: a device that leaves the item unacked shares it.
            const auto hears = [](Session& session, const std::string& text, const bool ack) {
                return testutil::waitFor([&]() {
                    for (const IncomingMessage& item : session.sync(ack)) {
                        if (item.text == text) {
                            return true;
                        }
                    }
                    return false;
                });
            };
            const auto pastPause = [&utc]() { utc.store(utc.load() + kSecondsPerHour + 1); };

            std::unique_ptr<Session> gina = accountAt(
                "bz-epochs-gina", "rlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p");
            std::unique_ptr<Session> hal = accountAt(
                "bz-epochs-hal", "slkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p");
            const EpochNumber start = epochAt(utc.load());
            CHECK(gina->ownEpochs().size() == kCardEpochs);
            CHECK(gina->ownEpochs().front().n == start);
            CHECK(gina->ownEpochReserveSeconds() == epochEnd(start + 1) - utc.load());
            CHECK(!gina->ownEpochReserveLow());
            const EpochPublic firstEpoch = gina->ownEpochs().front();

            addByInvite(*gina, hal->inviteUri(), "epochs");
            CHECK(testutil::waitFor([&]() {
                hal->sync();
                return hal->contactIsPending(gina->fingerprint());
            }));
            hal->acceptContactRequest(gina->fingerprint());
            CHECK(testutil::waitFor([&]() {
                gina->sync();
                return gina->canWriteTo(hal->fingerprint());
            }));

            const fs::path twinDir = scratch / "bz-epochs-gina2";
            fs::remove(twinDir);
            Session::importAccountBundle(gina->accountBundle(DeviceRole::ePrimary), twinDir);
            const std::unique_ptr<Session> gina2 = Session::open(twinDir, std::string{});
            CHECK(gina2->ownEpochs() == gina->ownEpochs());
            gina2->setEpochClock(clock);
            gina2->setFetchTransport(directDial);
            gina2->setOutboundLinks(courierFor());
            gina2->registerAccount();
            CHECK(testutil::waitFor([&]() {
                gina2->sync();
                gina->sync();
                return gina2->hasContact(hal->fingerprint());
            }));

            const std::size_t heldForHal = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[hal->fingerprint()].size();
            }();
            utc.store(epochStart(start + 1) + kSecondsPerDay);
            CHECK(gina->ownEpochReserveSeconds() < kEpochSeconds);
            gina->flushPendingEchoes();
            gina2->flushPendingEchoes();
            CHECK(keysOf("bz-epochs-gina", start + 2) == 0);
            pastPause();
            gina->flushPendingEchoes();
            gina2->flushPendingEchoes();
            CHECK(keysOf("bz-epochs-gina", start + 2) == 1);
            CHECK(keysOf("bz-epochs-gina2", start + 2) == 1);
            const std::string madeFirst = gina->ownEpochs().back().by;
            const std::string madeSecond = gina2->ownEpochs().back().by;
            CHECK(madeFirst != madeSecond);
            CHECK(testutil::waitFor([&]() {
                gina->sync(false);
                return keysOf("bz-epochs-gina", start + 2) == 2;
            }));
            CHECK(testutil::waitFor([&]() {
                gina2->sync();
                return keysOf("bz-epochs-gina2", start + 2) == 2;
            }));
            CHECK(gina->ownEpochs() == gina2->ownEpochs());
            CHECK(gina->ownEpochs().back().n == start + 2);
            CHECK(gina->ownEpochs().back().by == std::min(madeFirst, madeSecond));
            std::printf("TestDeliveryPass: two devices made epoch %lld at once; both use the key of %s\n",
                static_cast<long long>(start + 2), std::min(madeFirst, madeSecond).c_str());

            pastPause();
            gina->sync();
            gina->sendMessage(hal->fingerprint(), "while you were away");
            CHECK(testutil::waitFor([&]() {
                gina->sync();
                gina2->sync();
                const std::lock_guard<std::mutex> lock(m.mu);
                // The message and a card; a device that heard the other one sent it sends none.
                return m.mailbox[hal->fingerprint()].size() >= heldForHal + 2;
            }));

            utc.store(epochStart(start + 2) + kSecondsPerDay);
            gina->flushPendingEchoes();
            pastPause();
            gina->flushPendingEchoes();
            CHECK(keysOf("bz-epochs-gina", start + 3) == 1);
            CHECK(testutil::waitFor([&]() {
                gina2->sync();
                return keysOf("bz-epochs-gina2", start + 3) == 1;
            }));
            pastPause();
            gina2->flushPendingEchoes();
            CHECK(keysOf("bz-epochs-gina2", start + 3) == 1);
            CHECK(gina2->ownEpochs() == gina->ownEpochs());
            CHECK(keysOf("bz-epochs-gina", start) == 0);
            CHECK(testutil::waitFor([&]() {
                gina->sync();
                const std::lock_guard<std::mutex> lock(m.mu);
                return ContactCard::verify(fromBase64(m.certFor.at(gina->fingerprint())))
                           .epochs.front()
                           .n
                    == start + 2;
            }));

            CHECK(hears(*hal, "while you were away", true));
            hal->sendMessage(gina->fingerprint(), "back again");
            CHECK(hears(*gina, "back again", false));
            CHECK(hears(*gina2, "back again", true));

            gina->sendMessage(hal->fingerprint(), "after the turn");
            pastPause();
            CHECK(testutil::waitFor([&]() {
                gina->sync();
                for (const IncomingMessage& item : hal->sync()) {
                    if (item.text == "after the turn") {
                        return true;
                    }
                }
                return false;
            }));

            const DeviceCredential halIdentity = deviceOf(scratch / "bz-epochs-hal");
            const auto sealedFromHal = [&](const std::string& text, const EpochPublic& epoch) {
                nlohmann::json inner = {{"v", 1}, {"type", "text"},
                    {"id", toHex(randomBytes(kMessageIdBytes))}, {"from", hal->fingerprint()},
                    {"sentAt", nowMillis()}, {"text", text}};
                signAuthorship(inner, halIdentity, /*withCert=*/false);
                const std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[gina->fingerprint()].push_back({inner.at("id").get<std::string>(),
                    "content",
                    sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({inner}))),
                        epoch)});
            };
            sealedFromHal("to an erased epoch", firstEpoch);
            sealedFromHal("to this epoch", gina->ownEpochs().front());
            bool sawErased = false;
            bool sawCurrent = false;
            for (const IncomingMessage& item : gina->sync()) {
                sawErased = sawErased || item.text == "to an erased epoch";
                sawCurrent = sawCurrent || item.text == "to this epoch";
            }
            CHECK(!sawErased);
            CHECK(sawCurrent);

            (void)gina2->sync();
            int unreadable = 0;
            gina2->onUnreadableMail([&unreadable]() { ++unreadable; });
            const auto lastIdFor = [&](const std::string& account) {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.mailbox[account].back().id;
            };
            const auto stillPending = [&](const std::string& account, const std::string& id) {
                const std::lock_guard<std::mutex> lock(m.mu);
                const std::vector<Mock::Item>& box = m.mailbox[account];
                return std::any_of(box.begin(), box.end(), [&](const Mock::Item& item) {
                    return item.id == id && !item.ackedBy.contains(gina2->deviceId());
                });
            };
            const auto readNow = [](Session& session, const std::string& text) {
                for (const IncomingMessage& item : session.sync()) {
                    if (item.text == text) {
                        return true;
                    }
                }
                return false;
            };
            const auto intoDevice = [&](Session& to, const fs::path& toDir, nlohmann::json inner,
                                        const DeviceCredential& by) {
                inner["v"] = 1;
                inner["id"] = toHex(randomBytes(kMessageIdBytes));
                inner["from"] = gina->fingerprint();
                inner["sentAt"] = nowMillis();
                signAuthorship(inner, by, /*withCert=*/false);
                const Key sealing
                    = Key::fromPrivatePem(AccountDb(toDir, std::string{}).text("device-sealing.pem"));
                const std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[gina->fingerprint()].push_back({inner.at("id").get<std::string>(), "device",
                    hybrid::seal(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({inner}))),
                        Key::fromPublicDer(sealing.publicDer()), deviceKid(to.deviceId())),
                    to.deviceId()});
            };

            {
                const DeviceCredential ginaDevice = deviceOf(scratch / "bz-epochs-gina");
                const EpochPublic held = gina->ownEpochs().back();
                const Key raced = Key::generateSealing();
                const EpochPublic racedEpoch{held.n + 1, held.g, gina->deviceId(), raced.publicDer()};
                sealedFromHal("sealed before its key came", racedEpoch);
                const std::string racedId = lastIdFor(gina->fingerprint());
                CHECK(!readNow(*gina2, "sealed before its key came"));
                CHECK(stillPending(gina->fingerprint(), racedId));
                CHECK(unreadable == 0);
                intoDevice(*gina2, twinDir,
                    {{"type", "device.epochs"},
                        {"epochs", nlohmann::json::array({{{"n", racedEpoch.n}, {"g", racedEpoch.g},
                                       {"by", racedEpoch.by}, {"pem", raced.privatePem()}}})}},
                    ginaDevice);
                CHECK(readNow(*gina2, "sealed before its key came"));
                CHECK(testutil::waitFor([&]() {
                    gina2->sync();
                    return !stillPending(gina->fingerprint(), racedId);
                }));
                std::printf("TestDeliveryPass: a letter sealed before its key came was read once "
                            "device.epochs arrived\n");
            }

            {
                const Identity halRoot
                    = Identity::fromPrivatePem(AccountDb(scratch / "bz-epochs-hal", std::string{}).text("root.pem"));
                const DeviceKeys tab = DeviceKeys::generate();
                const Bytes tabCert = DeviceCertificate::issue(
                    halRoot, DevicePublic::of(tab), DeviceRole::eSecondary, nowSeconds());
                const DeviceCredential tabKey(Identity::fromPrivatePem(tab.signingPem()), tabCert);
                nlohmann::json fromTab = {{"v", 1}, {"type", "text"},
                    {"id", toHex(randomBytes(kMessageIdBytes))}, {"from", hal->fingerprint()},
                    {"sentAt", nowMillis()}, {"text", "from hal's new tablet"}};
                signAuthorship(fromTab, tabKey, /*withCert=*/false);
                {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    m.mailbox[gina->fingerprint()].push_back({fromTab.at("id").get<std::string>(),
                        "content",
                        sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({fromTab}))),
                            gina->ownEpochs().front())});
                }
                const std::string tabId = lastIdFor(gina->fingerprint());
                CHECK(!readNow(*gina2, "from hal's new tablet"));
                CHECK(stillPending(gina->fingerprint(), tabId));
                bool asked = false;
                CHECK(testutil::waitFor([&]() {
                    gina2->flushPendingEchoes();
                    for (const IncomingMessage& item : hal->sync()) {
                        asked = asked
                            || (item.contentType == kTypeContactKnows
                                && item.fromFingerprint == gina->fingerprint());
                    }
                    return asked;
                }));
                nlohmann::json introduced = {{"v", 1}, {"type", kTypeContactKnows},
                    {"id", toHex(randomBytes(kMessageIdBytes))}, {"from", hal->fingerprint()},
                    {"sentAt", nowMillis()}, {kKnowsField, nlohmann::json::array()}};
                signAuthorship(introduced, tabKey, /*withCert=*/true);
                {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    m.mailbox[gina->fingerprint()].push_back({introduced.at("id").get<std::string>(),
                        "content",
                        sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({introduced}))),
                            gina->ownEpochs().front())});
                }
                CHECK(readNow(*gina2, "from hal's new tablet"));
                std::printf("TestDeliveryPass: a letter of an unknown device of a contact waited, the "
                            "contact was asked, and the device's certificate let it be read\n");
            }

            {
                const DeviceKeys stranger = DeviceKeys::generate();
                const std::string strangerDevice = DeviceCertificate::verify(DeviceCertificate::issue(
                    Identity::generate(), DevicePublic::of(stranger), DeviceRole::ePrimary, nowSeconds()))
                                                       .device;
                sealedFromHal("sealed to a key no device of ours made",
                    EpochPublic{gina->ownEpochs().front().n, gina->ownEpochs().front().g, strangerDevice,
                        Key::generateSealing().publicDer()});
                const std::string strayId = lastIdFor(gina->fingerprint());
                CHECK(!readNow(*gina2, "sealed to a key no device of ours made"));
                CHECK(unreadable == 1);
                CHECK(testutil::waitFor([&]() {
                    gina2->sync();
                    return !stillPending(gina->fingerprint(), strayId);
                }));
            }
            gina2->onUnreadableMail({});

            utc.store(epochEnd(gina->ownEpochs().back().n) - kLowEpochReserveDays * kSecondsPerDay + 1);
            CHECK(gina->ownEpochReserveLow());
        }

        {
            const auto accountNamed = [&](const std::string& name, const std::string& dest) {
                const fs::path dir = scratch / name;
                fs::remove(dir);
                std::unique_ptr<Session> session
                    = Session::create(dir, AccountKind::eUser, endpoint, std::string{});
                {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    m.destFor[session->fingerprint()] = dest;
                }
                session->registerAccount();
                session->setFetchTransport(directDial);
                session->setOutboundLinks(courierFor());
                return session;
            };
            const auto opened = [&](const std::string& name) {
                std::unique_ptr<Session> session = Session::open(scratch / name, std::string{});
                session->setFetchTransport(directDial);
                session->setOutboundLinks(courierFor());
                return session;
            };
            const auto refusedForRole = [](const std::function<void()>& step) {
                try {
                    step();
                } catch (const DeviceRoleRefusal&) {
                    return true;
                } catch (const std::exception&) {
                    return false;
                }
                return false;
            };
            const auto hearsText = [](Session& session, const std::string& text) {
                std::optional<IncomingMessage> heard;
                CHECK(testutil::waitFor([&]() {
                    for (const IncomingMessage& item : session.sync()) {
                        if (item.text == text) {
                            heard = item;
                        }
                    }
                    return heard.has_value();
                }));
                return *heard;
            };
            // A card is dated by the second: the next device's must be newer than the last one's.
            const auto waitPastPublished = [&](const std::string& account) {
                const std::int64_t publishedAt = [&]() {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    return ContactCard::verify(fromBase64(m.certFor[account])).issuedAt;
                }();
                CHECK(testutil::waitFor([&]() { return nowSeconds() > publishedAt; }));
            };
            const auto sealedTo = [&](const std::string& account, const nlohmann::json& inner,
                                      const EpochPublic& epoch) {
                const std::lock_guard<std::mutex> lock(m.mu);
                m.mailbox[account].push_back({inner.at("id").get<std::string>(), "content",
                    sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({inner}))),
                        epoch)});
            };

            const std::unique_ptr<Session> ann = accountNamed(
                "bz-devices-ann", "tlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p");
            const std::unique_ptr<Session> ben = accountNamed(
                "bz-devices-ben", "ulkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p");
            CHECK(ann->isPrimary());
            CHECK(ann->ownDevices().size() == 1);
            CHECK(ann->ownDevices().front().current);
            addByInvite(*ann, ben->inviteUri(), "devices");
            CHECK(testutil::waitFor([&]() {
                ben->sync();
                return ben->contactIsPending(ann->fingerprint());
            }));
            ben->acceptContactRequest(ann->fingerprint());
            CHECK(testutil::waitFor([&]() {
                ann->sync();
                return ann->canWriteTo(ben->fingerprint());
            }));
            CHECK(ben->contactDevices(ann->fingerprint()).size() == 1);
            CHECK(ben->contactDevices(ann->fingerprint()).front().id == ann->deviceId());

            const Bytes tabletBundle = ann->exportAccountBytes("pw", DeviceRole::eSecondary);
            fs::remove(scratch / "bz-devices-tab");
            Session::importAccountBytes(tabletBundle, scratch / "bz-devices-tab", "pw");
            const std::unique_ptr<Session> tab = opened("bz-devices-tab");
            CHECK(tab->fingerprint() == ann->fingerprint());
            CHECK(tab->role() == DeviceRole::eSecondary);
            CHECK(tab->deviceId() != ann->deviceId());
            CHECK(!AccountDb(scratch / "bz-devices-tab", std::string{}).has("root.pem"));
            const std::string cardBeforeTablet = [&]() {
                std::lock_guard<std::mutex> lock(m.mu);
                return m.certFor[ann->fingerprint()];
            }();
            tab->registerAccount();
            {
                std::lock_guard<std::mutex> lock(m.mu);
                CHECK(m.certFor[ann->fingerprint()] == cardBeforeTablet);
            }
            CHECK(testutil::waitFor([&]() {
                (void)tab->sync();
                (void)ann->sync();
                const std::vector<OwnDevice> devices = ann->ownDevices();
                return std::any_of(devices.begin(), devices.end(),
                    [&](const OwnDevice& device) { return device.id == tab->deviceId(); });
            }));
            CHECK(refusedForRole([&]() { tab->disableI2pDest(); }));
            CHECK(refusedForRole([&]() { tab->setDelegationDays(kMaxDelegationDays, true); }));
            CHECK(refusedForRole([&]() { (void)tab->refreshOwnCard(); }));
            CHECK(!tab->refreshI2pTransientIfDue(0, kMaxDelegationDays * kSecondsPerDay));

            fs::remove(scratch / "bz-devices-twin");
            Session::importAccountBytes(tabletBundle, scratch / "bz-devices-twin", "pw");
            const std::unique_ptr<Session> twin = opened("bz-devices-twin");
            CHECK(twin->deviceId() == tab->deviceId());
            bool twinTaken = false;
            waitPastPublished(ann->fingerprint());
            try {
                twin->registerAccount();
            } catch (const ApiError& error) {
                twinTaken = error.code == ErrorCode::eDeviceTaken;
            }
            CHECK(twinTaken);

            CHECK(refusedForRole([&]() { (void)tab->exportAccountBytes("pw", DeviceRole::eSecondary); }));
            CHECK(refusedForRole([&]() { (void)tab->exportAccountBytes("pw", DeviceRole::ePrimary); }));
            CHECK(refusedForRole([&]() { (void)tab->pairingBundle(DeviceRole::eSecondary, newLinkKey()); }));
            CHECK(refusedForRole([&]() { (void)tab->startPairing({}, DeviceRole::eSecondary); }));
            CHECK(refusedForRole([&]() { tab->revokeDevice(ann->deviceId()); }));
            CHECK(refusedForRole([&]() { tab->closeAccountOnServer(); }));
            CHECK(refusedForRole([&]() { tab->replaceOwnAddress(); }));
            CHECK(refusedForRole([&]() { (void)tab->signLogin("challenge"); }));
            CHECK(refusedForRole([&]() { (void)tab->loginSigner(); }));
            CHECK(refusedForRole([&]() { (void)tab->aliasErrandContext(); }));
            CHECK(!tab->aliasServicingDue());

            for (const DeviceRole role : {DeviceRole::ePrimary, DeviceRole::eSecondary}) {
                const Bytes key = newLinkKey();
                const DeviceKeys made = DeviceKeys::generate();
                const Bytes sealed = ann->pairingBundle(role, key)(DevicePublic::of(made));
                const std::string name
                    = role == DeviceRole::ePrimary ? "bz-devices-paired-1" : "bz-devices-paired-2";
                fs::remove(scratch / name);
                Session::importAccountBundle(
                    openPairBundle(key, completePairBundle(key, sealed, made)).bytes(), scratch / name);
                const std::unique_ptr<Session> paired = Session::open(scratch / name, std::string{});
                CHECK(paired->deviceId() == made.id());
                CHECK(paired->role() == role);
                CHECK(paired->fingerprint() == ann->fingerprint());
                CHECK(AccountDb(scratch / name, std::string{}).has("root.pem")
                    == (role == DeviceRole::ePrimary));
            }

            CHECK(testutil::waitFor([&]() {
                ann->sync();
                const std::vector<OwnDevice> devices = ann->ownDevices();
                return std::any_of(devices.begin(), devices.end(),
                    [&](const OwnDevice& device) { return device.id == tab->deviceId(); });
            }));
            ann->setDisplayName("Ann of two devices");
            CHECK(testutil::waitFor([&]() {
                ann->flushPendingEchoes();
                tab->sync();
                return tab->displayName() == "Ann of two devices";
            }));

            CHECK(ben->contactDevices(ann->fingerprint()).size() == 1);
            tab->sendMessage(ben->fingerprint(), "from the tablet");
            CHECK(hearsText(*ben, "from the tablet").fromDevice == tab->deviceId());
            CHECK(ben->contactDevices(ann->fingerprint()).size() == 2);
            CHECK(storedDeviceId(AccountDb(scratch / "bz-devices-tab", std::string{}))
                == tab->deviceId());

            {
                std::atomic<std::int64_t> tabUtc{
                    epochStart(epochAt(nowSeconds()) + 1) + kSecondsPerDay};
                tab->setEpochClock([&tabUtc]() { return tabUtc.load(); });
                tab->flushPendingEchoes();
                tabUtc.store(tabUtc.load() + kSecondsPerHour + 1);
                tab->flushPendingEchoes();
                tab->setEpochClock(systemUtcSeconds);
                for (const WireEvent& event : tab->connectionLog()) {
                    CHECK(!event.what.starts_with(kTypeAccountCard));
                }
            }

            const DeviceCredential tabletKey = deviceOf(scratch / "bz-devices-tab");
            const std::vector<EpochPublic> annBefore = ann->ownEpochs();
            {
                ContactCard forged = ContactCard::verify(fromBase64([&]() {
                    std::lock_guard<std::mutex> lock(m.mu);
                    return m.certFor[ann->fingerprint()];
                }()));
                forged.issuedAt = nowSeconds() + 1;
                forged.epochs.front() = {annBefore.front().n, kFirstEpochGeneration, tabletKey.device(),
                    Key::generateSealing().publicDer()};
                nlohmann::json offer = {{"v", 1}, {"type", kTypeAccountCard},
                    {"id", toHex(randomBytes(kMessageIdBytes))}, {"from", ann->fingerprint()},
                    {"sentAt", nowMillis()},
                    {kCardField, nlohmann::json::binary(forged.issue(tabletKey.signing()))},
                    {kKnowsField, nlohmann::json::array()}};
                signAuthorship(offer, tabletKey, /*withCert=*/false);
                sealedTo(ben->fingerprint(), offer, ben->ownEpochs().front());
                ben->sync();
                const nlohmann::json held = nlohmann::json::parse(
                    AccountDb(scratch / "bz-devices-ben", std::string{}).text("contacts"));
                for (const nlohmann::json& epoch : held.at(ann->fingerprint()).at("epochs")) {
                    CHECK(epoch.at("by").get<std::string>() != tabletKey.device());
                }
            }

            waitPastPublished(ann->fingerprint());
            ann->revokeDevice(tab->deviceId());
            const std::vector<OwnDevice> afterRevoke = ann->ownDevices();
            CHECK(afterRevoke.back().id == tab->deviceId());
            CHECK(afterRevoke.back().revoked);
            const auto lists = [&ann, &tab](const std::int64_t daysLater) {
                const std::int64_t at = systemUtcSeconds() + daysLater * kSecondsPerDay;
                ann->setEpochClock([at]() { return at; });
                const std::vector<OwnDevice> shown = ann->ownDevices();
                return std::any_of(shown.begin(), shown.end(),
                    [&tab](const OwnDevice& device) { return device.id == tab->deviceId(); });
            };
            constexpr std::int64_t kStillShownDays = 29;
            constexpr std::int64_t kHiddenDays = 30;
            CHECK(lists(kStillShownDays));
            CHECK(!lists(kHiddenDays));
            ann->setEpochClock(systemUtcSeconds);
            CHECK(ann->ownEpochs().front().g == kFirstRevocationNumber + 1);
            CHECK(ann->ownEpochs().front().by == ann->deviceId());

            std::atomic<bool> toldRevoked{false};
            tab->onDeviceRevoked([&toldRevoked]() { toldRevoked.store(true); });
            bool tabletRefused = false;
            try {
                (void)tab->sync();
            } catch (const ApiError& error) {
                tabletRefused = error.code == ErrorCode::eDeviceRevoked;
            }
            CHECK(tabletRefused);
            CHECK(toldRevoked.load());
            CHECK(!tab->deviceRevoked());
            tab->noteDeviceRevoked();
            CHECK(tab->deviceRevoked());
            CHECK(tab->switchedOff());
            tab->setSwitchedOff(false);
            CHECK(tab->switchedOff());
            CHECK(AccountDb(scratch / "bz-devices-tab", std::string{}).has("device-revoked"));

            CHECK(testutil::waitFor([&]() {
                ann->flushPendingEchoes();
                ben->sync();
                const std::vector<ContactDevice> devices = ben->contactDevices(ann->fingerprint());
                return devices.size() == 2 && devices.back().revoked
                    && devices.back().id == tab->deviceId();
            }));
            {
                nlohmann::json forged = {{"v", 1}, {"type", "text"},
                    {"id", toHex(randomBytes(kMessageIdBytes))}, {"from", ann->fingerprint()},
                    {"sentAt", nowMillis()}, {"text", "from a revoked tablet"}};
                signAuthorship(forged, tabletKey, /*withCert=*/true);
                sealedTo(ben->fingerprint(), forged, ben->ownEpochs().front());
                for (const IncomingMessage& item : ben->sync()) {
                    CHECK(item.text != "from a revoked tablet");
                }
            }

            CHECK(testutil::waitFor([&]() {
                ann->flushPendingEchoes();
                ben->sync();
                const nlohmann::json held = nlohmann::json::parse(
                    AccountDb(scratch / "bz-devices-ben", std::string{}).text("contacts"));
                const nlohmann::json& epochs = held.at(ann->fingerprint()).at("epochs");
                return std::any_of(epochs.begin(), epochs.end(), [](const nlohmann::json& epoch) {
                    return epoch.at("g").get<EpochGeneration>() == kFirstRevocationNumber + 1;
                });
            }));
            ben->sendMessage(ann->fingerprint(), "after the revocation");
            Bytes sealedAfter;
            const Bytes newKid = ann->ownEpochs().front().kid();
            CHECK(testutil::waitFor([&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                for (const Mock::Item& item : m.mailbox[ann->fingerprint()]) {
                    if (item.cls == "content" && hybrid::sealedKid(item.payload) == newKid) {
                        sealedAfter = item.payload;
                    }
                }
                return !sealedAfter.empty();
            }));
            EpochRing tabletRing;
            tabletRing.addAll(nlohmann::json::parse(
                AccountDb(scratch / "bz-devices-tab", std::string{}).text("epochs")));
            CHECK_THROWS(tabletRing.open(sealedAfter));
            CHECK(hearsText(*ann, "after the revocation").fromDevice == ben->deviceId());

            {
                const std::unique_ptr<Session> desk = accountNamed(
                    "bz-pair-desk", "vlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p");
                const Bytes key = newLinkKey();
                const DeviceKeys made = DeviceKeys::generate();
                const Bytes sealed = desk->pairingBundle(DeviceRole::ePrimary, key)(DevicePublic::of(made));
                fs::remove(scratch / "bz-pair-phone");
                Session::importAccountBundle(
                    openPairBundle(key, completePairBundle(key, sealed, made)).bytes(),
                    scratch / "bz-pair-phone");
                const std::unique_ptr<Session> phone = opened("bz-pair-phone");
                waitPastPublished(desk->fingerprint());
                (void)phone->refreshOwnCard();
                waitPastPublished(desk->fingerprint());
                phone->registerAccount();
                const auto holds = [](Session& session, const std::string& device) {
                    const std::vector<OwnDevice> devices = session.ownDevices();
                    return std::any_of(devices.begin(), devices.end(),
                        [&](const OwnDevice& own) { return own.id == device && !own.revoked; });
                };
                CHECK(testutil::waitFor([&]() {
                    phone->flushPendingEchoes();
                    desk->sync();
                    return holds(*desk, phone->deviceId());
                }));
                phone->setDisplayName("named on the phone");
                CHECK(testutil::waitFor([&]() {
                    phone->flushPendingEchoes();
                    desk->sync();
                    return desk->displayName() == "named on the phone";
                }));
                desk->setDisplayName("named on the desk");
                CHECK(testutil::waitFor([&]() {
                    desk->flushPendingEchoes();
                    phone->sync();
                    return phone->displayName() == "named on the desk";
                }));
                std::printf("TestDeliveryPass: a paired primary that published its card before registering "
                            "is known to the one that paired it\n");
            }

            {
                const std::unique_ptr<Session> kim = accountNamed(
                    "bz-left-kim", "wlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p");
                const std::unique_ptr<Session> lou = accountNamed(
                    "bz-left-lou", "xlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p");
                addByInvite(*kim, lou->inviteUri(), "kim");
                CHECK(testutil::waitFor([&]() {
                    lou->sync();
                    return lou->contactIsPending(kim->fingerprint());
                }));
                lou->acceptContactRequest(kim->fingerprint());
                CHECK(testutil::waitFor([&]() {
                    kim->sync();
                    return kim->canWriteTo(lou->fingerprint());
                }));

                const Bytes key = newLinkKey();
                const DeviceKeys made = DeviceKeys::generate();
                const Bytes sealed = kim->pairingBundle(DeviceRole::ePrimary, key)(DevicePublic::of(made));
                fs::remove(scratch / "bz-left-phone");
                Session::importAccountBundle(
                    openPairBundle(key, completePairBundle(key, sealed, made)).bytes(),
                    scratch / "bz-left-phone");
                const std::unique_ptr<Session> phone = opened("bz-left-phone");
                waitPastPublished(kim->fingerprint());
                phone->registerAccount();
                phone->setDisplayName("kim on the phone");
                const auto selfWaitsForKim = [&]() {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    return std::any_of(m.mailbox[kim->fingerprint()].begin(),
                        m.mailbox[kim->fingerprint()].end(), [&](const Mock::Item& item) {
                            return item.cls == "device" && item.forDevice.empty()
                                && item.ackedBy.contains(phone->deviceId())
                                && !item.ackedBy.contains(kim->deviceId());
                        });
                };
                CHECK(testutil::waitFor([&]() {
                    phone->flushPendingEchoes();
                    return selfWaitsForKim();
                }));
                CHECK(testutil::waitFor([&]() {
                    kim->sync();
                    return kim->displayName() == "kim on the phone";
                }));
                const auto holdsActive = [](Session& session, const std::string& device) {
                    const std::vector<OwnDevice> devices = session.ownDevices();
                    return std::any_of(devices.begin(), devices.end(),
                        [&](const OwnDevice& own) { return own.id == device && !own.revoked; });
                };
                CHECK(holdsActive(*kim, phone->deviceId()));
                std::printf("TestDeliveryPass: a device offline while another registered read that "
                            "one's self-message when it came back\n");

                const auto lastLetterFor = [&](Session& to, const fs::path& toDir) {
                    EpochRing ring;
                    ring.addAll(SecretBytes(AccountDb(toDir, std::string{}).get("epochs").value()));
                    const std::lock_guard<std::mutex> lock(m.mu);
                    const Mock::Item& item = m.mailbox[to.fingerprint()].back();
                    return nlohmann::json::from_cbor(unpadFromLadder(ring.open(item.payload)).bytes()).at(0);
                };
                const auto sendAndWeigh = [&](const std::string& text) {
                    const std::size_t before = [&]() {
                        const std::lock_guard<std::mutex> lock(m.mu);
                        return m.mailbox[lou->fingerprint()].size();
                    }();
                    phone->sendMessage(lou->fingerprint(), text);
                    CHECK(testutil::waitFor([&]() {
                        phone->flushPendingEchoes();
                        const std::lock_guard<std::mutex> lock(m.mu);
                        return m.mailbox[lou->fingerprint()].size() > before;
                    }));
                    return lastLetterFor(*lou, scratch / "bz-left-lou");
                };
                const nlohmann::json first = sendAndWeigh("first from the phone");
                CHECK(!carriedCert(first).empty());
                CHECK(hearsText(*lou, "first from the phone").fromDevice == phone->deviceId());
                lou->sendMessage(kim->fingerprint(), "lou answers");
                CHECK(hearsText(*phone, "lou answers").fromFingerprint == lou->fingerprint());
                const nlohmann::json second = sendAndWeigh("second from the phone");
                CHECK(carriedCert(second).empty());
                CHECK(hearsText(*lou, "second from the phone").fromDevice == phone->deviceId());
                std::printf("TestDeliveryPass: a new device's certificate went with its letters until "
                            "the contact named it as known\n");

                const auto listedAs = [](Session& session, const std::string& device) {
                    for (const OwnDevice& own : session.ownDevices()) {
                        if (own.id == device) {
                            return std::optional<bool>(own.registered);
                        }
                    }
                    return std::optional<bool>();
                };
                const auto heldForPhoneAlone = [&]() {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    return std::count_if(m.mailbox[kim->fingerprint()].begin(),
                        m.mailbox[kim->fingerprint()].end(), [&](const Mock::Item& item) {
                            return item.ackedBy.contains(kim->deviceId())
                                && !item.ackedBy.contains(phone->deviceId());
                        });
                };
                kim->setDisplayName("named while the phone is away");
                CHECK(testutil::waitFor([&]() {
                    kim->flushPendingEchoes();
                    return heldForPhoneAlone() > 0;
                }));
                CHECK_THROWS(kim->clearDeviceQueue(kim->deviceId()));
                kim->clearDeviceQueue(phone->deviceId());
                CHECK(heldForPhoneAlone() == 0);
                CHECK(listedAs(*kim, phone->deviceId()) == std::optional<bool>(false));
                CHECK(holdsActive(*kim, phone->deviceId()));
                phone->registerAccount();
                {
                    const Session::ContactFetchContext watched = kim->contactFetchContext();
                    const std::unique_ptr<Client> waiter = Session::makeEventClient(watched);
                    (void)Session::waitForMail(
                        *waiter, Client::MailWait::eAtOnce, *watched.keptMail, *watched.devices);
                    CHECK(watched.devices->moved());
                    kim->flushPendingEchoes();
                }
                CHECK(listedAs(*kim, phone->deviceId()) == std::optional<bool>(true));
                std::printf("TestDeliveryPass: a primary cleared another device's queue; the device "
                            "stayed listed and registered again\n");

                phone->leaveAccount();
                const Session::ContactFetchContext context = kim->contactFetchContext();
                const std::unique_ptr<Client> waiter = Session::makeEventClient(context);
                (void)Session::waitForMail(
                    *waiter, Client::MailWait::eAtOnce, *context.keptMail, *context.devices);
                CHECK(context.devices->moved());
                waitPastPublished(kim->fingerprint());
                kim->flushPendingEchoes();
                CHECK(!holdsActive(*kim, phone->deviceId()));
                {
                    const std::lock_guard<std::mutex> lock(m.mu);
                    CHECK(ContactCard::verify(fromBase64(m.certFor[kim->fingerprint()]))
                              .revocation.revokes(phone->deviceId()));
                    CHECK(!m.listed[kim->fingerprint()].contains(phone->deviceId()));
                }
                CHECK(testutil::waitFor([&]() {
                    kim->flushPendingEchoes();
                    lou->sync();
                    const std::vector<ContactDevice> devices = lou->contactDevices(kim->fingerprint());
                    return std::any_of(devices.begin(), devices.end(), [&](const ContactDevice& device) {
                        return device.id == phone->deviceId() && device.revoked;
                    });
                }));
                std::printf("TestDeliveryPass: a device that left was revoked by the primary that saw "
                            "it, and the contact learned it from the card\n");
            }
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

    std::fprintf(stderr, "TestDeliveryPass passed (bob sent %d, alice sent %d)\n", bobSent, aliceSent);
    return 0;
} catch (...) {
    return testutil::failed();
}
