// Bazarish project (c) 2026
#include "ApiClient.hpp"
#include "Client.hpp"

#include "DeviceTestKit.hpp"
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
#include <type_traits>

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

static_assert(std::is_same_v<decltype(AddressKeys::sealingPem), SecretBytes>);
static_assert(std::is_same_v<decltype(AddressKeys::signingPem), SecretBytes>);
static_assert(std::is_same_v<decltype(tunnel::Request::body), SecretBytes>);
static_assert(std::is_same_v<decltype(&ApiClient::postSecret),
    ApiResponse (ApiClient::*)(const std::string&, const SecretBytes&)>);

int main()
{
    bazarish::setSelfHostedFacadeOnLoopback(true);
    const devicetest::Account aliceAccount;
    const DeviceCredential& alice = aliceAccount.device;
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
    int usageAnswers = 0;
    server.get("/v1/messaging/storage-usage", [&](const http::Request& request) {
        ++usageAnswers;
        sawMethod = request.method;
        sawPath = request.path;
        sawQuery = request.query("wait");
        sawDevice = request.header(teststub::kCallerDeviceHeader);
        http::Response response;
        response.body = nlohmann::json{{"used", 7}}.dump();
        return response;
    });
    server.post("/v1/messaging/clients", [&](const http::Request& request) {
        sawBody = request.body;
        sawDevice = request.header(teststub::kCallerDeviceHeader);
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
        ApiClient api(alice, endpoint);
        const ApiResponse response = api.get("/v1/messaging/storage-usage", "wait=30");
        CHECK(response.status == 200);
        CHECK(response.json().at("used") == 7);
        CHECK(sawMethod == "GET");
        CHECK(sawPath == "/v1/messaging/storage-usage");
        CHECK(sawQuery == "30");
        CHECK(sawDevice == aliceAccount.keys.id());
        CHECK(stub.opened() == 1);

        const ApiResponse posted
            = api.postJson("/v1/messaging/clients", {{"install", "abc123"}});
        CHECK(posted.status == 200);
        CHECK(nlohmann::json::parse(sawBody).at("install") == "abc123");
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
        CHECK(sawCaller == aliceAccount.fingerprint());
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        CHECK(api.get("/v1/account/i2p-status").status == 200);
        CHECK(nodeStub.opened() == 1);
        CHECK(stub.opened() == 3);
        CHECK(!api.serverBehindFacadeDown());

        const int answeredBefore = usageAnswers;
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        stub.answerNextWithTheLastAnswer();
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        CHECK(usageAnswers == answeredBefore + 2);
        CHECK(stub.opened() == 4);
    }

    {
        ApiClient api(alice, endpoint);
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
        ApiClient api(alice, endpoint);
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
        ServerEndpoint unnamed = endpoint;
        unnamed.serverFingerprint.clear();
        ApiClient blank(alice, unnamed);
        CHECK_THROWS(blank.get("/v1/messaging/storage-usage"));
        unnamed.serverFingerprint = "not a fingerprint";
        ApiClient garbled(alice, unnamed);
        CHECK_THROWS(garbled.get("/v1/messaging/storage-usage"));
    }

    {
        ServerEndpoint impostor = endpoint;
        impostor.serverFingerprint = Identity::generate().fingerprint();
        ApiClient api(alice, impostor);
        const auto ownCheckFailed = [&api]() {
            try {
                (void)api.get("/v1/messaging/storage-usage");
            } catch (const ApiError&) {
                return false;
            } catch (const std::runtime_error&) {
                return true;
            }
            return false;
        };
        CHECK(ownCheckFailed());
        CHECK(api.linkFailure() == LinkFailure::eServerRefused);
        CHECK(ownCheckFailed());
    }

    {
        const Bytes card = ServerCard::issue(serverIdentity, ServerCard::Service::eMessaging,
            Key::fromPublicDer(serverSealing.publicDer()), static_cast<std::int64_t>(std::time(nullptr)));
        const auto answeringHellos = [&card](http::Server& facade, std::atomic<int>& hellos,
                                         const http::Response answer) {
            facade.get(std::string(tunnel::kServerCardPath), [card](const http::Request&) {
                http::Response response;
                response.contentType = "application/octet-stream";
                response.body = std::string(card.begin(), card.end());
                return response;
            });
            facade.post(std::string(tunnel::kTunnelPath), [&hellos, answer](const http::Request&) {
                ++hellos;
                return answer;
            });
        };
        constexpr std::size_t kNoiseBytes = 64;
        const Bytes noise = randomBytes(kNoiseBytes);
        http::Response noiseAnswer;
        noiseAnswer.contentType = "application/octet-stream";
        noiseAnswer.body = std::string(noise.begin(), noise.end());
        http::Response notFound;
        notFound.status = 404;
        notFound.body = makeErrorEnvelope(ErrorCode::eRequestFailed, "no such route").dump();
        for (const http::Response& answer : {noiseAnswer, notFound}) {
            http::Server refusing(localOptions());
            std::atomic<int> hellos{0};
            answeringHellos(refusing, hellos, answer);
            ServerEndpoint refused = endpoint;
            refused.facades[0].port = refusing.start();
            ApiClient api(alice, refused);
            const auto unanswered = [&api]() {
                try {
                    (void)api.get("/v1/messaging/storage-usage");
                } catch (const ApiError& error) {
                    return error.httpStatus == 0 && !error.code.has_value();
                }
                return false;
            };
            CHECK(unanswered());
            CHECK(hellos.load() == 1);
            CHECK(api.linkFailure() == LinkFailure::eServerRefused);
            CHECK(unanswered());
            CHECK(hellos.load() == 2);
            refusing.stop();
        }
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
        ApiClient api(alice, both);
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
        ApiClient api(alice, dead);
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
        ApiClient api(alice, behind);
        const auto refused = [&api]() {
            try {
                (void)api.get("/v1/messaging/storage-usage");
            } catch (const ApiError&) {
                return true;
            }
            return false;
        };
        CHECK(!api.serverBehindFacadeDown());
        CHECK(refused());
        CHECK(hellos.load() == 1);
        CHECK(api.serverBehindFacadeDown());
        CHECK(api.linkFailure() == LinkFailure::eServerDown);
        CHECK(refused());
        CHECK(hellos.load() == 2);
        CHECK(api.serverBehindFacadeDown());

        bazarish::i2p::networkLost();
        CHECK(refused());
        CHECK(hellos.load() == 2);
        CHECK(api.linkFailure() == LinkFailure::eNoNetwork);
        CHECK(!api.serverBehindFacadeDown());
        bazarish::i2p::networkChanged();
        CHECK(refused());
        CHECK(hellos.load() == 3);
        CHECK(api.linkFailure() == LinkFailure::eServerDown);

        upstreamless.stop();
        CHECK(refused());
        CHECK(!api.serverBehindFacadeDown());
        CHECK(api.linkFailure() == LinkFailure::eServerUnreachable);

        http::Server::Options samePort = localOptions();
        samePort.port = behind.facades[0].port;
        http::Server returned(samePort);
        teststub::Tunnel returnedStub(
            returned, serverIdentity, serverSealing, ServerCard::Service::eMessaging);
        returned.get("/v1/messaging/storage-usage", [](const http::Request&) {
            http::Response response;
            response.body = nlohmann::json{{"used", 0}}.dump();
            return response;
        });
        CHECK(returned.start() == samePort.port);
        CHECK(refused());
        CHECK(returnedStub.opened() == 0);
        bazarish::i2p::backend::noteCarryReturned();
        CHECK(api.get("/v1/messaging/storage-usage").status == 200);
        CHECK(returnedStub.opened() == 1);
        returned.stop();
    }

    std::fprintf(stderr, "TestApiClient passed\n");
    return 0;
}
