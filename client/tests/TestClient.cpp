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
    const Key serverSealing = Key::generateSealing();
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
            CHECK(card.servingSealingKeyDer == serverSealing.publicDer());
            respondJson(response, {{"quotaBytes", 10 * 1024 * 1024}});
        }));

    server.get("/v1/messaging/destination",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            respondJson(response,
                {{"dest", aliceDest}, {"servingKey", toBase64(serverSealing.publicDer())}});
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
            outcome.sealed = ContactCard::issue(bob, static_cast<std::int64_t>(std::time(nullptr)),
                bobDest, bobSealing.publicDer(), serverSealing.publicDer());
            return outcome;
        }

        CHECK(op == "resolve");
        CHECK(toDest == resolverDest);
        const ResolveQuery query = resolveQueryFromJson(nlohmann::json::parse(sealed));
        if (query.alias == "ghost") {
            outcome.errorCode = "ALIAS_UNKNOWN";
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
                {{"pending", nlohmann::json::array({{{"id", "blob1"}, {"class", "content"}},
                                {{"id", "blob2"}, {"class", "contact"}}})}});
        }));

    server.get("/v1/messaging/pending/blob1",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            response.contentType = "application/octet-stream";
            response.body = std::string("\x01\x02\x03opaque", 9);
        }));

    server.post("/v1/messaging/ack",
        stub([&](const http::Request& request, http::Response& response) {
            (void)requireCaller(request);
            CHECK(nlohmann::json::parse(request.body).at("blobId") == "blob1");
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

    Client client(Identity::fromPrivatePem(alice.privatePem()), "client01", endpoint);

    {
        const Key aliceSealing = Key::generateSealing();
        const DestinationInfo serving = client.myDestination();
        CHECK(serving.dest == aliceDest);
        const PublishResult result = client.publishCard(aliceSealing.publicDer(), serving);
        CHECK(result.quotaBytes == 10u * 1024 * 1024);
        CHECK(result.dest == aliceDest);
        CHECK(result.servingSealingKeyDer == serverSealing.publicDer());
        CHECK(!result.cardDer.empty());
    }

    {
        const Descriptor descriptor{bob.fingerprint(), bobDest};
        const ContactInfo info = client.fetchCard(descriptor, directDial);
        CHECK(info.card.fingerprint() == bob.fingerprint());
        CHECK(info.card.dest == bobDest);
        CHECK(info.card.servingSealingKey().publicDer() == serverSealing.publicDer());
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
    {
        const Descriptor descriptor = client.resolveAlias("bob", resolver, now, directDial);
        CHECK(descriptor.fingerprint == bob.fingerprint());
        CHECK(descriptor.dest == bobDest);

        CHECK(rejects([&]() { (void)client.resolveAlias("ghost", resolver, now, directDial); }));

        const ResolverCoordinate wrongRoot{Identity::generate().fingerprint(), resolverDest};
        CHECK(rejects([&]() { (void)client.resolveAlias("bob", wrongRoot, now, directDial); }));

        CHECK(rejects([&]() { (void)client.resolveAlias("swap", resolver, now, directDial); }));
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

        const Bytes blob = client.fetchBlob("blob1");
        CHECK(blob.size() == 9);
        CHECK(blob[0] == 0x01);

        client.ack("blob1");
    }

    {
        const Key recipientSealing = Key::fromPublicDer(serverSealing.publicDer());
        const Bytes pass = Bytes(kDeliveryPassSize, 0x33);
        const Bytes sealed
            = sealDeliveryEnvelope("content", bob.fingerprint(), "msg-1", pass, recipientSealing);
        const Bytes plain = hybrid::unseal(sealed, serverSealing);
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
