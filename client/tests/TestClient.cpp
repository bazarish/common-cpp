// Bazarish project (c) 2026
#include "Client.hpp"

#include "TunnelStub.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/Pass.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/ResolvePuzzle.hpp>

#include <bazarish/HttpServer.hpp>

#include "TestUtil.hpp"

#include <functional>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <stdexcept>
#include <string>
#include <thread>

using namespace bazarish;
using namespace bazarish::client;

namespace {

constexpr std::uint32_t kBusyBits = 2;
constexpr std::size_t kBusyStampBytes = 16;
constexpr unsigned char kBusyStampFill = 0x5a;

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
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
    return options;
}

void respondJson(http::Response& response, const nlohmann::json& body)
{
    response.contentType = "application/json";
    response.body = body.dump();
}

}  // namespace

int main()
{
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    const std::int64_t now = nowSeconds();

    const Identity serverIdentity = Identity::generate();
    const std::string serverFp = serverIdentity.fingerprint();
    const Key servingSealing = Key::generateSealing();
    const std::string aliceDest = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
    const std::string bobDest = "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";

    const Identity resolverRoot = Identity::generate();
    const Identity resolverDelegated = Identity::generate();
    const std::string resolverDest = "flkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
    const std::int64_t resolverWeek = 7 * 24 * 3600;
    const Bytes resolverDelegationDer
        = DelegationCertificate::issue(resolverRoot, resolverDelegated, now, now + resolverWeek);

    const Identity alice = Identity::generate();
    const Identity bob = Identity::generate();

    http::Server server(localOptions());

    server.post("/v1/account/card",
        stub([&](const http::Request& request, http::Response& response) {
            const std::string user = requireCaller(request);
            const Bytes der
                = fromBase64(nlohmann::json::parse(request.body).at("card").get<std::string>());
            const ContactCard card = ContactCard::verify(der);
            CHECK(card.fingerprint() == user);
            CHECK(!card.sealingPublicKeyDer.empty());
            CHECK(card.dest == aliceDest);
            CHECK(card.servingSealingKeyDer == servingSealing.publicDer());
            respondJson(response, {{"quotaBytes", 10 * 1024 * 1024}});
        }));

    server.get("/v1/messaging/destination",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            respondJson(response, {{"dest", aliceDest}});
        }));

    const FetchTransport directDial = [&](const std::string& toDest, const std::string& op,
                                          const Bytes& sealed) {
        FetchOutcome outcome;
        if (op == "card") {
            CHECK(toDest == bobDest);
            const CardFetchQuery query = cardFetchQueryFromJson(nlohmann::json::parse(sealed));
            CHECK(query.fingerprint == bob.fingerprint());
            const Key bobSealing = Key::generateSealing();
            outcome.ok = true;
            ContactCard card;
            card.issuedAt = static_cast<std::int64_t>(std::time(nullptr));
            card.dest = bobDest;
            card.sealingPublicKeyDer = bobSealing.publicDer();
            card.servingSealingKeyDer = servingSealing.publicDer();
            card.presenceKeyDer = Key::generateX25519().publicDer();
            card.presenceDest = bobDest;
            outcome.sealed = card.issue(bob);
            return outcome;
        }

        CHECK(op == "resolve");
        CHECK(toDest == resolverDest);
        const ResolveQuery query = resolveQueryFromJson(nlohmann::json::parse(sealed));
        if (query.alias == "guarded" && query.word != "secret") {
            outcome.errorCode = "ALIAS_UNKNOWN";
            return outcome;
        }
        if (query.alias == "busy" && (query.stamp.empty()
                || !puzzleSolved(fromHex(query.stamp), query.nonce, kBusyBits))) {
            const Bytes stamp(kBusyStampBytes, kBusyStampFill);
            const std::string challenge
                = nlohmann::json{{"stamp", toHex(stamp)}, {"bits", kBusyBits}}.dump();
            outcome.errorCode = kProofRequiredCode;
            outcome.refusal = Bytes(challenge.begin(), challenge.end());
            return outcome;
        }
        if (query.alias == "ghost") {
            outcome.errorCode = "ALIAS_UNKNOWN";
            return outcome;
        }
        if (query.alias == "down") {
            outcome.errorCode = "HTTP_503";
            return outcome;
        }
        const std::string recordAlias = query.alias == "swap" ? "other" : query.alias;
        const Descriptor descriptor{bob.fingerprint(), bobDest};
        const ResolveRecord record{recordAlias, descriptor, now, now + resolverWeek};
        const ResolveResponse resp{signResolveRecord(record, resolverDelegated),
            resolverDelegationDer, AliasCertificate::issue(bob, recordAlias, now)};
        const std::string respJson = toJson(resp).dump();
        outcome.ok = true;
        outcome.sealed = Bytes(respJson.begin(), respJson.end());
        return outcome;
    };

    server.post("/v1/messaging/clients",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            CHECK(request.header("X-Bazarish-Client") == "client01");
            CHECK(nlohmann::json::parse(request.body).at("clientId") == "client01");
            respondJson(response, {{"ok", true}});
        }));

    server.post("/v1/messaging/passes",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            const nlohmann::json asked = nlohmann::json::parse(request.body).at("passes");
            CHECK(asked.size() == 2);
            CHECK(fromBase64(asked.at(0).get<std::string>()).size() == kDeliveryPassSize);
            respondJson(response, {{"ok", true}, {"held", asked.size()}});
        }));

    server.post("/v1/messaging/passes/revoke",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            CHECK(nlohmann::json::parse(request.body).at("passes").size() == 1);
            respondJson(response, {{"revoked", 1}});
        }));

    server.get("/v1/messaging/pending",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            respondJson(response,
                {{"pending",
                    nlohmann::json::array({{{"id", "blob1"}, {"class", "content"}, {"bytes", 9}},
                        {{"id", "blob2"}, {"class", "contact"}, {"bytes", 4}}})}});
        }));

    server.post("/v1/messaging/fetch",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            CHECK(nlohmann::json::parse(request.body).at("ids")
                == nlohmann::json::array({"blob1", "gone"}));
            const std::string opaque("\x01\x02\x03opaque", 9);
            nlohmann::json items = nlohmann::json::array();
            items.push_back({{"id", "blob1"},
                {"blob",
                    nlohmann::json::binary(std::vector<std::uint8_t>(opaque.begin(), opaque.end()))}});
            const std::vector<std::uint8_t> answer = nlohmann::json::to_cbor({{"items", items}});
            response.contentType = "application/cbor";
            response.body = std::string(answer.begin(), answer.end());
        }));

    server.post("/v1/messaging/ack",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            CHECK(nlohmann::json::parse(request.body).at("ids")
                == nlohmann::json::array({"blob1", "blob2"}));
            respondJson(response, {{"ok", true}});
        }));

    const Identity stubServerIdentity = Identity::generate();
    const Key stubServerSealing = Key::generateSealing();
    bazarish::teststub::Tunnel tunnelStub(server, stubServerIdentity, stubServerSealing);
    const int port = server.start();
    CHECK(port > 0);

    ServerEndpoint endpoint;
    endpoint.serverFingerprint = stubServerIdentity.fingerprint();
    endpoint.facades = {Facade{"127.0.0.1", port}};

    Client client(Identity::fromPrivatePem(alice.privatePem()), "client01", endpoint);

    {
        const Key aliceSealing = Key::generateSealing();
        DestinationInfo serving = client.myDestination();
        CHECK(serving.dest == aliceDest);
        CHECK(serving.servingSealingKeyDer.empty());
        serving.servingSealingKeyDer = servingSealing.publicDer();
        ContactCard content;
        content.sealingPublicKeyDer = aliceSealing.publicDer();
        content.presenceKeyDer = Key::generateX25519().publicDer();
        content.presenceDest = aliceDest;
        const PublishResult result = client.publishCard(content, serving);
        CHECK(result.quotaBytes == 10u * 1024 * 1024);
        CHECK(result.dest == aliceDest);
        CHECK(result.servingSealingKeyDer == servingSealing.publicDer());
        CHECK(!result.cardDer.empty());
    }

    {
        const Descriptor descriptor{bob.fingerprint(), bobDest};
        const ContactInfo info = client.fetchCard(descriptor, directDial);
        CHECK(info.card.fingerprint() == bob.fingerprint());
        CHECK(info.card.dest == bobDest);
        CHECK(info.card.servingSealingKey().publicDer() == servingSealing.publicDer());
        CHECK(!info.card.sealingPublicKeyDer.empty());
    }

    const ResolverCoordinate resolver{resolverRoot.fingerprint(), resolverDest};
    const auto rejects = [&](const auto& fn) {
        try {
            fn();
        } catch (const std::exception&) {
            return true;
        }
        return false;
    };
    const auto unknown = [&](const auto& fn) {
        try {
            fn();
        } catch (const AliasUnknown&) {
            return true;
        } catch (const std::exception&) {
            return false;
        }
        return false;
    };
    {
        const Descriptor descriptor = client.resolveAlias({"bob"}, resolver, now, directDial);
        CHECK(descriptor.fingerprint == bob.fingerprint());
        CHECK(descriptor.dest == bobDest);

        CHECK(unknown(
            [&]() { (void)client.resolveAlias({"guarded"}, resolver, now, directDial); }));
        CHECK(unknown(
            [&]() { (void)client.resolveAlias({"guarded", "wrong"}, resolver, now, directDial); }));
        CHECK(client.resolveAlias(parseAliasQuery("!Guarded-Secret"), resolver, now, directDial)
                  .fingerprint
            == bob.fingerprint());

        bool solved = false;
        CHECK(client
                  .resolveAlias({"busy"}, resolver, now, directDial, [&solved]() { solved = true; })
                  .fingerprint
            == bob.fingerprint());
        CHECK(solved);

        CHECK(unknown([&]() { (void)client.resolveAlias({"ghost"}, resolver, now, directDial); }));
        CHECK(rejects([&]() { (void)client.resolveAlias({"down"}, resolver, now, directDial); }));
        CHECK(!unknown([&]() { (void)client.resolveAlias({"down"}, resolver, now, directDial); }));

        const ResolverCoordinate wrongRoot{Identity::generate().fingerprint(), resolverDest};
        CHECK(rejects([&]() { (void)client.resolveAlias({"bob"}, wrongRoot, now, directDial); }));
        CHECK(!unknown([&]() { (void)client.resolveAlias({"bob"}, wrongRoot, now, directDial); }));

        CHECK(rejects([&]() { (void)client.resolveAlias({"swap"}, resolver, now, directDial); }));
        CHECK(!unknown([&]() { (void)client.resolveAlias({"swap"}, resolver, now, directDial); }));
    }

    {
        client.registerThisClient();
        client.registerPasses({Bytes(kDeliveryPassSize, 0x44), Bytes(kDeliveryPassSize, 0x55)});
        CHECK(client.revokePasses({Bytes(kDeliveryPassSize, 0x44)}) == 1);
    }

    {
        const std::vector<PendingEntry> pending = client.listPending();
        CHECK(pending.size() == 2);
        CHECK(pending[0].id == "blob1");
        CHECK(pending[0].deliveryClass == "content");
        CHECK(pending[1].deliveryClass == "contact");
        CHECK(pending[0].bytes == 9);

        const std::vector<FetchedItem> fetched = client.fetch({"blob1", "gone"});
        CHECK(fetched.size() == 1);
        CHECK(fetched[0].id == "blob1");
        CHECK(fetched[0].blob.size() == 9);
        CHECK(fetched[0].blob[0] == 0x01);

        client.ack({"blob1", "blob2"});
    }

    {
        const Key recipientSealing = Key::fromPublicDer(servingSealing.publicDer());
        const Bytes pass = Bytes(kDeliveryPassSize, 0x33);
        const Bytes sealed
            = sealDeliveryEnvelope("content", bob.fingerprint(), "msg-1", pass, recipientSealing);
        const Bytes plain = hybrid::unseal(sealed, servingSealing);
        const nlohmann::json inner = nlohmann::json::parse(plain.begin(), plain.end());
        CHECK(inner.at("class") == "content");
        CHECK(inner.at("mailbox") == bob.fingerprint());
        CHECK(inner.at("deliveryId") == "msg-1");
        CHECK(fromBase64(inner.at("pass").get<std::string>()) == pass);
    }

    server.stop();

    std::fprintf(stderr, "TestClient passed\n");
    {
        const std::string key = "0123456789abcdef0123456789abcdef";
        const std::string first = deliveryIdFor(key, "msg-1", "mailbox-a");
        CHECK(first.size() == 32);
        CHECK(deliveryIdFor(key, "msg-1", "mailbox-a") == first);
        CHECK(deliveryIdFor(key, "msg-1", "mailbox-b") != first);
        CHECK(deliveryIdFor(key, "msg-2", "mailbox-a") != first);
        CHECK(deliveryIdFor("another-secret", "msg-1", "mailbox-a") != first);
    }

    return 0;
}
