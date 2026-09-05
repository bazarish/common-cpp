// Bazarish project (c) 2026
#include "ApiClient.hpp"
#include <bazarish/ServerDescriptor.hpp>

#include <bazarish/Auth.hpp>
#include <bazarish/Cms.hpp>
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
                request.path, Bytes(request.body.begin(), request.body.end()),
                request.header("X-Bazarish-Client"));
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
                "/v1/messaging/clients", Bytes(request.body.begin(), request.body.end()),
                request.header("X-Bazarish-Client"));
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

    // --- Sessions ---
    //
    // What every request after the first one is supposed to carry. The stub here
    // is the messaging half: it opens a session against a serving key it holds,
    // and then answers either scheme, reporting which one it saw.
    {
        // How long a failed open stops us asking again, as a policy rather than a
        // wait a test would have to sit through: a server that answered is
        // arguing and is left alone for a long time; silence is the network.
        CHECK(ApiClient::sessionBackoffSeconds(0) < ApiClient::sessionBackoffSeconds(503));
        CHECK(ApiClient::sessionBackoffSeconds(503) == ApiClient::sessionBackoffSeconds(401));

        const Key serving = Key::generateSealing();
        http::Server sessionServer(localOptions());
        // What the stub decides to do next, driven by the test.
        int refuseOpenWith = 0;       // non-zero: answer the open with this status
        bool refuseNextMac = false;   // answer one MAC'd request SESSION_INVALID
        std::string lastScheme;       // "signature" or "session"
        int opens = 0;
        Bytes sessionSecret;
        std::string sessionId;
        Bytes sessionKey;

        sessionServer.post("/v1/auth/session", [&](const http::Request& request) {
            http::Response response;
            if (refuseOpenWith != 0) {
                response.status = refuseOpenWith;
                response.body = makeErrorEnvelope(
                    ErrorCode::eDeliveryRejected, "no sessions here").dump();
                return response;
            }
            // Opening one is the one thing a session may not do (a leaked secret
            // must not renew itself for ever), so the stub insists on a signature
            // exactly as the server does.
            CHECK(!auth::hasSessionHeaders(collectAuthHeaders(request)));
            (void)auth::verifyRequest(collectAuthHeaders(request), nowSeconds(), "POST",
                "/v1/auth/session", Bytes(request.body.begin(), request.body.end()),
                request.header("X-Bazarish-Client"));
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const Bytes opened
                = cms::unseal(fromBase64(body.at("sealed").get<std::string>()), serving);
            const nlohmann::json inner = nlohmann::json::parse(opened.begin(), opened.end());
            sessionSecret = fromBase64(inner.at("secret").get<std::string>());
            sessionId = toHex(sha256(sessionSecret)).substr(0, 32);
            sessionKey = auth::deriveSessionKey(sessionSecret, sessionId);
            ++opens;
            const Key replyKey
                = Key::fromPublicDer(fromBase64(inner.at("replyKey").get<std::string>()));
            const std::string answer
                = nlohmann::json{{"expiresUnix", nowSeconds() + 3600}}.dump();
            response.body = nlohmann::json{{"sealed",
                toBase64(cms::seal(Bytes(answer.begin(), answer.end()), replyKey))}}.dump();
            return response;
        });

        sessionServer.get("/v1/messaging/storage-usage", [&](const http::Request& request) {
            http::Response response;
            auth::Headers headers = collectAuthHeaders(request);
            for (const char* const name :
                {auth::kHeaderSession, auth::kHeaderSeq, auth::kHeaderMac}) {
                if (request.hasHeader(name)) {
                    headers[name] = request.header(name);
                }
            }
            if (auth::hasSessionHeaders(headers)) {
                if (refuseNextMac) {
                    refuseNextMac = false;
                    response.status = 401;
                    response.body = makeErrorEnvelope(
                        ErrorCode::eSessionInvalid, "unknown or expired session").dump();
                    return response;
                }
                // The device is inside the MAC, so verifying needs the header the
                // request actually arrived with.
                (void)auth::verifyMac(headers, sessionKey, nowSeconds(), "GET",
                    "/v1/messaging/storage-usage", Bytes(),
                    request.header("X-Bazarish-Client"));
                lastScheme = "session";
            } else {
                (void)auth::verifyRequest(headers, nowSeconds(), "GET",
                    "/v1/messaging/storage-usage", Bytes(),
                    request.header("X-Bazarish-Client"));
                lastScheme = "signature";
            }
            response.body = nlohmann::json{{"used", 0}}.dump();
            return response;
        });

        const int sessionPort = sessionServer.start();
        CHECK(sessionPort > 0);
        ServerEndpoint sessionEndpoint;
        sessionEndpoint.serverFingerprint = "unused-here";
        sessionEndpoint.facades = {Facade{false, "127.0.0.1", sessionPort, {}}};

        {
            ApiClient api(alice, "abc123", sessionEndpoint);
            // Nothing to seal a secret to yet: every request signs.
            CHECK(api.get("/v1/messaging/storage-usage").status == 200);
            CHECK(lastScheme == "signature");
            CHECK(opens == 0);

            // Once the account knows its serving key, the first request opens a
            // session and every one after it carries a MAC.
            api.setSessionSealingKey(serving.publicDer());
            CHECK(api.get("/v1/messaging/storage-usage").status == 200);
            CHECK(lastScheme == "session");
            CHECK(opens == 1);
            CHECK(api.get("/v1/messaging/storage-usage").status == 200);
            CHECK(lastScheme == "session");
            CHECK(opens == 1);  // the same session, not one per request

            // A session refused mid-request: the client signs that request rather
            // than retrying the same way, and opens a fresh session for the next.
            refuseNextMac = true;
            CHECK(api.get("/v1/messaging/storage-usage").status == 200);
            CHECK(lastScheme == "signature");
            CHECK(api.get("/v1/messaging/storage-usage").status == 200);
            CHECK(lastScheme == "session");
            CHECK(opens == 2);
        }

        // A server that answers the open with a refusal is believed: the client
        // keeps signing even once the route starts working again.
        {
            ApiClient api(alice, "abc123", sessionEndpoint);
            refuseOpenWith = 503;
            api.setSessionSealingKey(serving.publicDer());
            CHECK(api.get("/v1/messaging/storage-usage").status == 200);
            CHECK(lastScheme == "signature");
            refuseOpenWith = 0;
            CHECK(api.get("/v1/messaging/storage-usage").status == 200);
            CHECK(lastScheme == "signature");  // still inside the long wait
        }

        sessionServer.stop();
    }

    std::fprintf(stderr, "TestApiClient passed\n");
    return 0;
}
