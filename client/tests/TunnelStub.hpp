// Bazarish project (c) 2026
#pragma once

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Tunnel.hpp>

#include <atomic>
#include <cstdio>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish::teststub {

inline constexpr const char* kCallerHeader = "x-bazarish-test-caller";

class Tunnel {
public:
    Tunnel(bazarish::http::Server& server, const Identity& serverIdentity, const Key& sealing)
        : sealing_(Key::fromPrivatePem(sealing.privatePem()))
    {
        const Bytes card = ServerCard::issue(serverIdentity,
            Key::fromPublicDer(sealing.publicDer()), static_cast<std::int64_t>(std::time(nullptr)));
        server.get(std::string(bazarish::tunnel::kServerCardPath),
            [card](const bazarish::http::Request&) {
                bazarish::http::Response response;
                response.contentType = "application/octet-stream";
                response.body = std::string(card.begin(), card.end());
                return response;
            });
        server.routeAsync("POST", std::string(bazarish::tunnel::kTunnelPath),
            [this, &server](const bazarish::http::Request& request,
                bazarish::http::Responder respond) -> std::optional<bazarish::http::Response> {
                try {
                    serve(server, request, std::move(respond));
                } catch (const std::exception& error) {
                    std::fprintf(stderr, "tunnel stub: %s\n", error.what());
                    bazarish::http::Response failed;
                    failed.status = 500;
                    return failed;
                }
                return std::nullopt;
            });
    }

    int opened() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return opened_;
    }

    void refuseNext() { refuseNext_ = true; }

    void refuseNextOpaquely() { refuseOpaquely_ = true; }

private:
    void serve(bazarish::http::Server& server, const bazarish::http::Request& request,
        bazarish::http::Responder respond)
    {
        const Bytes frame(request.body.begin(), request.body.end());
        const auto sealed = [respond](const Bytes& body) {
            bazarish::http::Response response;
            response.contentType = "application/octet-stream";
            response.body = std::string(body.begin(), body.end());
            respond(std::move(response));
        };
        if (bazarish::tunnel::isHello(frame)) {
            const bazarish::tunnel::Hello hello = bazarish::tunnel::openHello(frame, sealing_);
            const std::string user
                = auth::verifyRequest(hello.signature, static_cast<std::int64_t>(std::time(nullptr)),
                    bazarish::tunnel::kHelloMethod, bazarish::tunnel::kHelloPath, hello.secret);
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                secrets_.push_back({hello.secret, user, 0});
                ++opened_;
            }
            sealed(bazarish::tunnel::sealWelcome(
                {static_cast<std::int64_t>(std::time(nullptr)) + 3600},
                Key::fromPublicDer(hello.replyKeyDer)));
            return;
        }

        const std::string handle = bazarish::tunnel::handleOf(frame);
        Bytes key;
        std::string caller;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            for (Opened& open : secrets_) {
                for (std::uint64_t seq = open.lastSeq + 1;
                    seq <= open.lastSeq + kHandleWindow; ++seq) {
                    if (auth::sessionHandle(open.secret, seq) == handle) {
                        open.lastSeq = seq;
                        key = bazarish::tunnel::deriveTunnelKey(
                            open.secret, toHex(sha256(open.secret)).substr(0, 32));
                        caller = open.user;
                        break;
                    }
                }
                if (!key.empty()) {
                    break;
                }
            }
        }
        if (key.empty()) {
            std::fprintf(stderr, "tunnel stub: no session for handle %s\n", handle.c_str());
            bazarish::http::Response response;
            response.status = 400;
            respond(std::move(response));
            return;
        }

        if (refuseOpaquely_) {
            refuseOpaquely_ = false;
            sealed(randomBytes(kOpaqueRefusalBytes));
            return;
        }
        if (refuseNext_) {
            refuseNext_ = false;
            bazarish::tunnel::Response inner;
            inner.status = 401;
            inner.contentType = "application/json";
            const std::string body
                = R"({"error":{"code":"SESSION_INVALID","message":"gone"}})";
            inner.body = Bytes(body.begin(), body.end());
            sealed(bazarish::tunnel::carry(
                handle, key, bazarish::tunnel::encodeResponse(inner)));
            return;
        }

        const bazarish::tunnel::Request carried
            = bazarish::tunnel::decodeRequest(bazarish::tunnel::open(frame, key));
        bazarish::http::Request inner;
        inner.method = carried.method;
        inner.path = carried.path;
        inner.target = carried.query.empty() ? carried.path : carried.path + "?" + carried.query;
        inner.body = std::string(carried.body.begin(), carried.body.end());
        for (const auto& [name, value] : carried.headers) {
            std::string lowered = name;
            for (char& c : lowered) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            inner.headers[lowered] = value;
        }
        inner.headers[kCallerHeader] = caller;
        server.dispatch(inner, [sealed, handle, key](bazarish::http::Response answer) {
            bazarish::tunnel::Response out;
            out.status = answer.status;
            out.contentType = answer.contentType;
            out.body = Bytes(answer.body.begin(), answer.body.end());
            sealed(bazarish::tunnel::carry(handle, key, bazarish::tunnel::encodeResponse(out)));
        });
    }

    static constexpr std::uint64_t kHandleWindow = 64;

    static constexpr std::size_t kOpaqueRefusalBytes = 64;

    struct Opened {
        Bytes secret;
        std::string user;
        std::uint64_t lastSeq = 0;
    };

    Key sealing_;
    mutable std::mutex mutex_;
    std::vector<Opened> secrets_;
    int opened_ = 0;
    std::atomic<bool> refuseNext_{false};
    std::atomic<bool> refuseOpaquely_{false};
};

}  // namespace bazarish::teststub
