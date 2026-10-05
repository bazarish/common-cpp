// Bazarish project (c) 2026
#pragma once

#include "bazarish/Auth.hpp"
#include "bazarish/Bytes.hpp"
#include "bazarish/Padding.hpp"
#include "bazarish/Crypto.hpp"

#include <cstdint>
#include <map>
#include <string>

namespace bazarish::tunnel {

inline constexpr int kFrameVersion = 1;

inline constexpr const char* kTunnelPath = "/t";
inline constexpr const char* kVouchedPrefix = "/v1/vouched/";

inline constexpr const char* kServerCardPath = "/v1/server/card";

inline constexpr const char* kHelloMethod = "BZ-TUNNEL";
inline constexpr const char* kHelloPath = "/hello";

struct Request {
    std::string method;
    std::string path;
    std::string query;
    std::map<std::string, std::string> headers;
    Bytes body;
    std::string contentType;
};

struct Response {
    int status = 0;
    std::string contentType;
    Bytes body;
};

struct Hello {
    Bytes secret;
    Bytes replyKeyDer;
    auth::Headers signature;
};

struct Welcome {
    std::int64_t expiresUnix = 0;
};

Bytes deriveTunnelKey(const Bytes& secret, const std::string& sessionId);

Bytes sealHello(const Hello& hello, const Key& serverSealingPublic);
Hello openHello(const Bytes& frame, const Key& serverSealingPrivate);

Bytes sealWelcome(const Welcome& welcome, const Key& replyKeyPublic);
Welcome openWelcome(const Bytes& sealed, const Key& replyKeyPrivate);

Bytes carry(const std::string& handle, const Bytes& tunnelKey, const Bytes& plaintext);
std::string handleOf(const Bytes& frame);
bool isHello(const Bytes& frame);
Bytes open(const Bytes& frame, const Bytes& tunnelKey);

Bytes encodeRequest(const Request& request);
Request decodeRequest(const Bytes& plaintext);
Bytes encodeResponse(const Response& response);
Response decodeResponse(const Bytes& plaintext);

}  // namespace bazarish::tunnel
