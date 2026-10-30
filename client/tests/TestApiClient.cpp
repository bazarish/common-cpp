// Bazarish project (c) 2026
#include "ApiClient.hpp"

#include "TunnelStub.hpp"
#include "../../src/I2pBackend.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/ServerDescriptor.hpp>

#include <bazarish/HttpServer.hpp>

#include "TestUtil.hpp"
#include <nlohmann/json.hpp>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <memory>
#include <stdexcept>

using namespace bazarish;
using namespace bazarish::client;

namespace {

http::Server::Options localOptions()
{
    http::Server::Options options;
    options.port = 0;
    return options;
}

}  // namespace

int main()
{
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    const Identity alice = Identity::generate();
    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();

    const Key nodeSealing = Key::generateSealing();

    http::Server server(localOptions());
    teststub::Tunnel stub(server, serverIdentity, serverSealing, ServerCard::Service::eMessaging);
    teststub::Tunnel nodeStub(
        server, serverIdentity, nodeSealing, ServerCard::Service::eServiceNode);

    std::string sawMethod;
    std::string sawPath;
    std::string sawQuery;
    std::string sawDevice;
    std::string sawBody;
    server.get("/v1/messaging/storage-usage", [&](const http::Request& request) {
        sawMethod = request.method;
        sawPath = request.path;
        sawQuery = request.query("wait");
        sawDevice = request.header("X-Bazarish-Client");
        http::Response response;
        response.body = nlohmann::json{{"used", 7}}.dump();
        return response;
    });
    server.post("/v1/messaging/clients", [&](const http::Request& request) {
        sawBody = request.body;
        sawDevice = request.header("X-Bazarish-Client");
        http::Response response;
        response.body = nlohmann::json{{"ok", true}}.dump();
        return response;
    });
    server.get("/v1/messaging/pending", [](const http::Request&) {
        http::Response response;
        response.status = 404;
        response.body = makeErrorEnvelope(ErrorCode::eClientUnregistered, "no account").dump();
        return response;
    });
    std::string sawCaller;
    server.get("/v1/account/i2p-status", [&](const http::Request& request) {
        sawCaller = request.header(teststub::kCallerHeader);
        http::Response response;
        response.body = nlohmann::json{{"approval", "approved"}}.dump();
        return response;
    });
    server.get("/v1/messaging/destination", [](const http::Request&) {
        http::Response response;
        response.status = 500;
        response.contentType = "text/plain";
        response.body = "internal boom";
        return response;
    });

    const int port = server.start();
    CHECK(port > 0);

    ServerEndpoint endpoint;
    endpoint.serverFingerprint = serverIdentity.fingerprint();
    endpoint.facades = {Facade{"127.0.0.1", port}};

    {
        ApiClient api(alice, "abc123", endpoint);
        const ApiResponse response = api.get("/v1/messaging/storage-usage", "wait=30");
        CHECK(response.status == 200);
        CHECK(response.json().at("used") == 7);
        CHECK(sawMethod == "GET");
        CHECK(sawPath == "/v1/messaging/storage-usage");
        CHECK(sawQuery == "30");
        CHECK(sawDevice == "abc123");
        CHECK(stub.opened() == 1);

        const ApiResponse posted
            = api.postJson("/v1/messaging/clients", {{"clientId", "abc123"}});
        CHECK(posted.status == 200);
        CHECK(nlohmann::json::parse(sawBody).at("clientId") == "abc123");
        CHECK(stub.opened() == 1);

        stub.refuseNext();
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        CHECK(stub.opened() == 2);

        stub.refuseNextOpaquely();
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        CHECK(stub.opened() == 3);

        CHECK(nodeStub.opened() == 0);
        CHECK(api.get("/v1/account/i2p-status").status == 200);
        CHECK(nodeStub.opened() == 1);
        CHECK(stub.opened() == 3);
        CHECK(sawCaller == alice.fingerprint());
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        CHECK(api.get("/v1/account/i2p-status").status == 200);
        CHECK(nodeStub.opened() == 1);
        CHECK(stub.opened() == 3);
    }

    {
        ApiClient api(alice, "abc123", endpoint);
        bool threw = false;
        try {
            (void)api.get("/v1/messaging/pending");
        } catch (const ApiError& error) {
            threw = true;
            CHECK(error.httpStatus == 404);
            CHECK(error.code.has_value());
            CHECK(error.code.value() == ErrorCode::eClientUnregistered);
        }
        CHECK(threw);
    }

    {
        ApiClient api(alice, "abc123", endpoint);
        bool threw = false;
        try {
            (void)api.get("/v1/messaging/destination");
        } catch (const ApiError& error) {
            threw = true;
            CHECK(error.httpStatus == 500);
            CHECK(!error.code.has_value());
        }
        CHECK(threw);
    }

    {
        ServerEndpoint impostor = endpoint;
        impostor.serverFingerprint = Identity::generate().fingerprint();
        ApiClient api(alice, "abc123", impostor);
        bool threw = false;
        try {
            (void)api.get("/v1/messaging/storage-usage");
        } catch (const ApiError&) {
            threw = true;
        }
        CHECK(threw);
    }

    {
        http::Server backend(localOptions());
        teststub::Tunnel backendStub(
            backend, serverIdentity, serverSealing, ServerCard::Service::eMessaging);
        backend.get("/v1/messaging/storage-usage", [](const http::Request&) {
            http::Response response;
            response.body = nlohmann::json{{"used", 0}}.dump();
            return response;
        });
        CHECK(backend.start() > 0);
        const auto relayTo = [&backend](http::Server& facade, std::atomic<int>& carried) {
            const auto relay = [&backend, &carried](const http::Request& request,
                                   http::Responder respond) -> std::optional<http::Response> {
                ++carried;
                backend.dispatch(request, std::move(respond));
                return std::nullopt;
            };
            facade.routeAsync("POST", std::string(tunnel::kTunnelPath), relay);
            facade.routeAsync("GET", std::string(tunnel::kServerCardPath), relay);
        };
        std::atomic<int> firstCarried{0};
        std::atomic<int> secondCarried{0};
        std::atomic<int> backCarried{0};
        auto first = std::make_unique<http::Server>(localOptions());
        relayTo(*first, firstCarried);
        const int firstPort = first->start();
        http::Server second(localOptions());
        relayTo(second, secondCarried);
        const int secondPort = second.start();

        ServerEndpoint both = endpoint;
        both.facades = {Facade{"127.0.0.1", firstPort}, Facade{"127.0.0.1", secondPort}};
        ApiClient api(alice, "abc123", both);
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        CHECK(firstCarried.load() > 0);
        CHECK(secondCarried.load() == 0);

        first->stop();
        first.reset();
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        const int carriedBySecond = secondCarried.load();
        CHECK(carriedBySecond > 0);

        http::Server::Options samePort = localOptions();
        samePort.port = firstPort;
        http::Server back(samePort);
        relayTo(back, backCarried);
        CHECK(back.start() == firstPort);
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        CHECK(secondCarried.load() == carriedBySecond + 1);
        CHECK(backCarried.load() == 0);
        back.stop();
        second.stop();
        backend.stop();
    }

    server.stop();

    {
        ServerEndpoint dead = endpoint;
        dead.facades[0].port = 1;
        ApiClient api(alice, "abc123", dead);
        bool threw = false;
        try {
            (void)api.get("/v1/messaging/storage-usage");
        } catch (const ApiError& error) {
            threw = true;
            CHECK(error.httpStatus == 0);
            CHECK(!error.code.has_value());
        }
        CHECK(threw);
    }

    {
        http::Server upstreamless(localOptions());
        const Bytes card = ServerCard::issue(serverIdentity, ServerCard::Service::eMessaging,
            Key::fromPublicDer(serverSealing.publicDer()), static_cast<std::int64_t>(std::time(nullptr)));
        upstreamless.get(std::string(tunnel::kServerCardPath), [card](const http::Request&) {
            http::Response response;
            response.contentType = "application/octet-stream";
            response.body = std::string(card.begin(), card.end());
            return response;
        });
        std::atomic<int> hellos{0};
        upstreamless.post(std::string(tunnel::kTunnelPath), [&hellos](const http::Request&) {
            ++hellos;
            http::Response response;
            response.status = 502;
            response.body = R"({"error":{"code":"UPSTREAM_UNAVAILABLE","message":"backend unreachable"}})";
            return response;
        });
        ServerEndpoint behind = endpoint;
        behind.facades[0].port = upstreamless.start();
        ApiClient api(alice, "abc123", behind);
        const auto refused = [&api]() {
            try {
                (void)api.get("/v1/messaging/storage-usage");
            } catch (const ApiError&) {
                return true;
            }
            return false;
        };
        CHECK(refused());
        CHECK(hellos.load() == 1);
        CHECK(refused());
        CHECK(hellos.load() == 1);
        bazarish::i2p::backend::noteCarryReturned();
        CHECK(refused());
        CHECK(hellos.load() == 2);
        upstreamless.stop();
    }

    CHECK(ApiClient::sessionBackoffSeconds(0) < ApiClient::sessionBackoffSeconds(401));
    CHECK(ApiClient::sessionBackoffSeconds(502) == ApiClient::sessionBackoffSeconds(0));

    std::fprintf(stderr, "TestApiClient passed\n");
    return 0;
}
