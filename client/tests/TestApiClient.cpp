// Bazarish project (c) 2026
#include "ApiClient.hpp"
#include <bazarish/ServerDescriptor.hpp>

#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>

#include <bazarish/HttpServer.hpp>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <stdexcept>
#include <filesystem>

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

http::Server::Options localOptions()
{
    http::Server::Options options;
    options.port = 0;  // the kernel picks one
    return options;
}

}  // namespace

// The stub server these tests talk to is a plain HTTP listener on localhost -
// the same shape as a stand on a LAN, and the reason that switch exists.
int main()
{
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    const Identity alice = Identity::generate();

    http::Server server(localOptions());

    // Echoes the verified caller fingerprint and the client header, proving
    // the request was correctly signed against the query-less path.
    server.get("/v1/account/subscription", [&](const http::Request& request) {
        http::Response response;
        std::string user;
        try {
            user = auth::verifyRequest(collectAuthHeaders(request), nowSeconds(), "GET",
                request.path, Bytes(request.body.begin(), request.body.end()));
        } catch (const std::exception& error) {
            response.status = 401;
            response.contentType = "text/plain";
            response.body = error.what();
            return response;
        }
        response.body
            = nlohmann::json{{"notAfter", 1234}, {"quotaBytes", 10}, {"user", user}}.dump();
        return response;
    });

    // A request signed for a secret base path must verify against the
    // stripped path, so the route lives under the base path but the auth
    // check uses the suffix.
    server.post("/s/secret/v1/messaging/clients", [&](const http::Request& request) {
        http::Response response;
        std::string user;
        try {
            user = auth::verifyRequest(collectAuthHeaders(request), nowSeconds(), "POST",
                "/v1/messaging/clients", Bytes(request.body.begin(), request.body.end()));
        } catch (const std::exception& error) {
            response.status = 401;
            response.contentType = "text/plain";
            response.body = error.what();
            return response;
        }
        CHECK(request.header("X-Bazarish-Client") == "abc123");
        const nlohmann::json body = nlohmann::json::parse(request.body);
        CHECK(body.at("clientId") == "abc123");
        response.body = nlohmann::json{{"ok", true}, {"user", user}}.dump();
        return response;
    });

    // Returns a typed error envelope.
    server.get("/v1/account/contact", [](const http::Request&) {
        http::Response response;
        response.status = 404;
        response.body
            = makeErrorEnvelope(ErrorCode::eClientUnregistered, "no account").dump();
        return response;
    });

    // Returns a non-envelope error body.
    server.get("/v1/messaging/pending", [](const http::Request&) {
        http::Response response;
        response.status = 500;
        response.contentType = "text/plain";
        response.body = "internal boom";
        return response;
    });

    // The private reseed: unauthenticated, and the one call that must stay on
    // clearnet because it is what bootstraps the I2P transport.
    server.get("/v1/messaging/reseed", [](const http::Request&) {
        http::Response response;
        response.body = R"({"routers":["cm91dGVy"]})";
        return response;
    });

    const int port = server.start();
    CHECK(port > 0);

    ServerEndpoint endpoint;
    endpoint.serverFingerprint = "unused-here";
    endpoint.facades = {Facade{false, "127.0.0.1", port, {}}};

    // A signed GET round-trips and the server derives alice's fingerprint
    // from the presented keys.
    {
        ApiClient api(alice, "abc123", endpoint);
        const ApiResponse response = api.get("/v1/account/subscription");
        CHECK(response.status == 200);
        const nlohmann::json body = response.json();
        CHECK(body.at("notAfter") == 1234);
        CHECK(body.at("user") == alice.fingerprint());
    }

    // The same client over a secret base path: the URL carries the prefix,
    // the signature is computed over the stripped path.
    {
        ServerEndpoint secret = endpoint;
        secret.facades[0].basePath = "/s/secret";
        ApiClient api(alice, "abc123", secret);
        const ApiResponse response = api.postJson("/v1/messaging/clients",
            {{"clientId", "abc123"}});
        CHECK(response.status == 200);
        CHECK(response.json().at("user") == alice.fingerprint());
    }

    // A typed error envelope surfaces as ApiError carrying the code.
    {
        ApiClient api(alice, "abc123", endpoint);
        bool threw = false;
        try {
            api.get("/v1/account/contact", "user=ghost");
        } catch (const ApiError& error) {
            threw = true;
            CHECK(error.httpStatus == 404);
            CHECK(error.code.has_value());
            CHECK(error.code.value() == ErrorCode::eClientUnregistered);
        }
        CHECK(threw);
    }

    // A non-envelope error keeps the status but carries no typed code.
    {
        ApiClient api(alice, "abc123", endpoint);
        bool threw = false;
        try {
            api.get("/v1/messaging/pending");
        } catch (const ApiError& error) {
            threw = true;
            CHECK(error.httpStatus == 500);
            CHECK(!error.code.has_value());
        }
        CHECK(threw);
    }

    // The reseed bootstraps the I2P transport itself, so it must never be routed
    // over an I2P facade - which would ask the router to start before it has a
    // netDb, while the reseed already holds the router lock. With an I2P facade
    // configured and preferred, getClearnet still lands on the clearnet one.
    {
        ServerEndpoint mixed;
        mixed.serverFingerprint = endpoint.serverFingerprint;
        mixed.facades = {Facade{false, "pgb6a4qhbfqx6mrxxjvhpxbsyf7hlpvxsl7hkeutqxvxpv4fzbaa.b32.i2p",
                             80, {}},
            endpoint.facades[0]};
        // A non-empty data dir is what makes I2P facades preferred.
        ApiClient api(alice, "abc123", mixed, std::filesystem::temp_directory_path() / "bz-i2p");
        const ApiResponse response = api.getClearnet("/v1/messaging/reseed");
        CHECK(response.status == 200);
        CHECK(response.json().at("routers").size() == 1);
    }

    server.stop();

    // A transport failure (nothing listening) is an ApiError with no HTTP
    // status and no typed code.
    {
        ServerEndpoint dead = endpoint;
        dead.facades[0].port = 1;  // Reserved; connection refused.
        ApiClient api(alice, "abc123", dead);
        bool threw = false;
        try {
            api.get("/v1/account/subscription");
        } catch (const ApiError& error) {
            threw = true;
            CHECK(error.httpStatus == 0);
            CHECK(!error.code.has_value());
        }
        CHECK(threw);
    }

    std::fprintf(stderr, "TestApiClient passed\n");
    return 0;
}
