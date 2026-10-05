// Bazarish project (c) 2026
#include "ApiClient.hpp"

#include "TunnelStub.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/ServerDescriptor.hpp>

#include <bazarish/HttpServer.hpp>

#include "TestUtil.hpp"
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
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

    http::Server server(localOptions());
    teststub::Tunnel stub(server, serverIdentity, serverSealing);

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
    endpoint.facades = {Facade{false, "127.0.0.1", port, {}}};

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

    // A card that names another server is not this server's card.
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

    CHECK(ApiClient::sessionBackoffSeconds(0) < ApiClient::sessionBackoffSeconds(503));
    CHECK(ApiClient::sessionBackoffSeconds(503) == ApiClient::sessionBackoffSeconds(401));

    std::fprintf(stderr, "TestApiClient passed\n");
    return 0;
}
