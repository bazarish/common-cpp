// Bazarish project (c) 2026
#include "ApiClient.hpp"

#include "TunnelStub.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/ServerDescriptor.hpp>

#include <bazarish/HttpServer.hpp>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <stdexcept>

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

http::Server::Options localOptions()
{
    http::Server::Options options;
    options.port = 0;  // the kernel picks one
    return options;
}

}  // namespace

// Everything a client says to its server goes through one sealed tunnel, so this
// test drives it over that transport rather than a plainer one that would pass
// while the real path was broken. The stub terminates the frame exactly as the
// messaging server does, and the routes behind it never learn they are inside
// one.
int main()
{
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    const Identity alice = Identity::generate();
    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();

    http::Server server(localOptions());
    teststub::Tunnel stub(server, serverIdentity, serverSealing);

    // What the carried request looked like when it came out the other side.
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
    // A typed refusal, as the real API answers one.
    server.get("/v1/messaging/pending", [](const http::Request&) {
        http::Response response;
        response.status = 404;
        response.body = makeErrorEnvelope(ErrorCode::eClientUnregistered, "no account").dump();
        return response;
    });
    // And one that is not an envelope at all.
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

    // A request rides the tunnel and arrives whole: method, path, query and the
    // device it speaks for, none of which the facade in between could have read.
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

        // The next request reuses the tunnel: an identity is presented once.
        const ApiResponse posted
            = api.postJson("/v1/messaging/clients", {{"clientId", "abc123"}});
        CHECK(posted.status == 200);
        CHECK(nlohmann::json::parse(sawBody).at("clientId") == "abc123");
        CHECK(stub.opened() == 1);

        // A tunnel refused mid-request: the client opens another rather than
        // retrying the same way, and the request still goes through.
        stub.refuseNext();
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        CHECK(stub.opened() == 2);

        // The same when the refusal says nothing at all: a frame this key cannot
        // open IS the refusal, because the outer answer is the one every carried
        // request gets. The client reads it as a lapsed session and opens
        // another tunnel, exactly as it does for a typed one.
        stub.refuseNextOpaquely();
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        CHECK(stub.opened() == 3);
    }

    // A typed error envelope from inside the frame surfaces as a typed error out
    // here: the outer exchange said 200, and the code came from within.
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

    // A refusal that is not an envelope keeps its status and carries no code.
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

    // A card that names another server is not this server's card. A facade may
    // withhold the card; one it made up must not be sealed to.
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

    // Nothing listening at all: an ApiError with no HTTP status and no code,
    // which is what tells a client the network went away rather than that the
    // server refused it - the difference the tunnel backoff is decided on.
    {
        ServerEndpoint dead = endpoint;
        dead.facades[0].port = 1;  // reserved; connection refused
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

    // How long a failed open stops us asking again, as a policy rather than a
    // wait a test would have to sit through: a server that answered is arguing
    // and is left alone for a long time; silence is the network.
    CHECK(ApiClient::sessionBackoffSeconds(0) < ApiClient::sessionBackoffSeconds(503));
    CHECK(ApiClient::sessionBackoffSeconds(503) == ApiClient::sessionBackoffSeconds(401));

    std::fprintf(stderr, "TestApiClient passed\n");
    return 0;
}
