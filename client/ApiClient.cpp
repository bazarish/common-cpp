// Bazarish project (c) 2026
#include "ApiClient.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/I2pHttp.hpp>

#include <bazarish/HttpClient.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>

namespace bazarish::client {

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

// How to talk to a clearnet facade. The facade is the untrusted last mile -
// security is end-to-end and anchored in the server fingerprint, not in TLS PKI
// - so a self-signed or proxy certificate is accepted.
bazarish::http::ClientOptions facadeOptions(const Facade& facade, const int readTimeoutSeconds)
{
    bazarish::http::ClientOptions options;
    options.tls = facade.tls;
    options.verifyPeer = false;
    options.connectTimeout = std::chrono::seconds(ApiClient::kConnectTimeoutSeconds);
    options.readTimeout = std::chrono::seconds(readTimeoutSeconds);
    options.writeTimeout = std::chrono::seconds(ApiClient::kWriteTimeoutSeconds);
    return options;
}

// How long to wait for our own outbound destination's tunnels on a cold start,
// and how long a dial to a facade may take once they are up.
// One dial, plus one more if the connection we kept had already been closed.
constexpr int kKeepAliveAttempts = 2;
constexpr int kOutboundReadySeconds = 180;
constexpr int kFacadeDialSeconds = 60;
// The secret a session key is derived from.
constexpr std::size_t kSessionSecretBytes = 32;
// The session id is local to each side (it fixes the MAC key together with the
// secret); only handles derived from the secret ever travel.
constexpr std::size_t kSessionIdChars = 32;

// Turns a non-2xx response into a typed ApiError. A recognized error
// envelope yields its code and message; anything else keeps the raw body.
[[noreturn]] void raiseFromResponse(const int status, const Bytes& body)
{
    const std::string text(body.begin(), body.end());
    try {
        const nlohmann::json document = nlohmann::json::parse(text);
        const std::optional<ParsedError> parsed = parseErrorEnvelope(document);
        if (parsed.has_value()) {
            // A refusal with nothing written on it is undiagnosable where it
            // surfaces, so it carries its status instead of an empty string.
            throw ApiError(parsed->code, status,
                parsed->message.empty()
                    ? ("server refused with status " + std::to_string(status))
                    : parsed->message);
        }
    } catch (const nlohmann::json::exception&) {
        // error-hiding: allowed - the body was not an error envelope, and the
        // ApiError thrown right below carries the status and the raw text.
    }
    throw ApiError(std::nullopt, status,
        text.empty() ? ("server answered status " + std::to_string(status) + " with no body")
                     : text);
}

}  // namespace

Facade parseFacadeUrl(const std::string& url)
{
    Facade facade;
    std::string rest = url;

    const std::string::size_type schemeEnd = rest.find("://");
    if (schemeEnd != std::string::npos) {
        const std::string scheme = rest.substr(0, schemeEnd);
        if (scheme == "https") {
            facade.tls = true;
        } else if (scheme != "http") {
            throw std::runtime_error("unsupported facade scheme: " + scheme);
        }
        rest = rest.substr(schemeEnd + 3);
    }
    if (rest.empty()) {
        throw std::runtime_error("empty facade URL");
    }

    const std::string::size_type slash = rest.find('/');
    const std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    facade.basePath = slash == std::string::npos ? std::string() : rest.substr(slash);
    while (facade.basePath.size() > 1 && facade.basePath.back() == '/') {
        facade.basePath.pop_back();
    }
    if (facade.basePath == "/") {
        facade.basePath.clear();
    }

    const std::string::size_type colon = authority.find(':');
    if (colon != std::string::npos) {
        facade.host = authority.substr(0, colon);
        try {
            facade.port = std::stoi(authority.substr(colon + 1));
        } catch (const std::exception&) {
            throw std::runtime_error("invalid facade port in: " + url);
        }
        if (facade.port <= 0 || facade.port > 65535) {
            throw std::runtime_error("invalid facade port in: " + url);
        }
    } else {
        facade.host = authority;
        facade.port = facade.tls ? 443 : 80;
    }
    if (facade.host.empty()) {
        throw std::runtime_error("empty facade host in: " + url);
    }
    return facade;
}

std::string facadeToUrl(const Facade& facade)
{
    std::string url = (facade.tls ? "https://" : "http://") + facade.host;
    const int defaultPort = facade.tls ? 443 : 80;
    if (facade.port != 0 && facade.port != defaultPort) {
        url += ":" + std::to_string(facade.port);
    }
    url += facade.basePath;
    return url;
}

nlohmann::json ApiResponse::json() const
{
    return nlohmann::json::parse(body.begin(), body.end());
}

ApiError::ApiError(
    const std::optional<ErrorCode> code, const int httpStatus, const std::string& message)
    : std::runtime_error(message)
    , code(code)
    , httpStatus(httpStatus)
{
}

ApiClient::ApiClient(const Identity& identity, std::string clientId, ServerEndpoint endpoint,
    std::filesystem::path i2pDataDir)
    : identity_(identity)
    , clientId_(std::move(clientId))
    , endpoint_(std::move(endpoint))
    , i2pDataDir_(std::move(i2pDataDir))
{
    // Point the "connected via" display at the preferred facade before the first
    // request confirms one (I2P is tried first, so it reads as the active one).
    if (!endpoint_.facades.empty()) {
        activeFacade_ = facadeOrder().front();
    }
}

bool ApiClient::facadeIsI2p(const Facade& facade)
{
    static const std::string kSuffix = ".b32.i2p";
    const std::string& host = facade.host;
    return host.size() >= kSuffix.size()
        && host.compare(host.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0;
}

// A facade this process serves itself, reached without touching the network.
// The address is compared literally: a name that resolves to loopback today is
// a name that resolves elsewhere tomorrow.
bool ApiClient::facadeIsOwnLoopback(const Facade& facade)
{
    if (!bazarish::selfHostedFacadeOnLoopback()) {
        return false;
    }
    return facade.host == "127.0.0.1" || facade.host == "::1";
}

std::vector<std::size_t> ApiClient::facadeOrder() const
{
    // The API is spoken over I2P and nothing else, so a facade that is not an I2P
    // address is not tried at all - there is no "first connection over clearnet"
    // to be had, which is when a client would otherwise show its address to the
    // server it is about to register with. A stand on a LAN turns the whole rule
    // off with one switch that says what it costs.
    const bool anything = bazarish::allowFacadeWithoutI2pForDevPurposes();
    std::vector<std::size_t> order;
    order.reserve(endpoint_.facades.size());
    for (std::size_t i = 0; i < endpoint_.facades.size(); ++i) {
        if (anything || facadeIsI2p(endpoint_.facades[i])
            || facadeIsOwnLoopback(endpoint_.facades[i])) {
            order.push_back(i);
        }
    }
    return order;
}

const std::string& ApiClient::clientId() const
{
    return clientId_;
}

const ServerEndpoint& ApiClient::endpoint() const
{
    return endpoint_;
}

bool ApiClient::ensureSessionLocked()
{
    // Renewed before it lapses, not after: the server tells us when it expires
    // exactly so a client never has to learn it from a refused request.
    constexpr std::int64_t kRenewLeadSeconds = 300;
    // How long we keep signing after a session was refused out of hand. Without
    // it, a server that answers every session with 401 would have us open one per
    // request forever.
    constexpr std::int64_t kBlockedForSeconds = 900;

    const std::int64_t now = nowSeconds();
    if (!sessionId_.empty() && now + kRenewLeadSeconds < sessionUntil_) {
        return true;
    }
    if (sessionSealingKeyDer_.empty() || now < sessionBlockedUntil_) {
        return false;  // nothing to seal to, or we are in the cooldown
    }
    sessionId_.clear();
    try {
        // Sealed to this user's serving key: only the server that operates the
        // destination can open it, so the facade in between carries a blob.
        const Bytes secret = randomBytes(kSessionSecretBytes);
        // A one-time key for the answer, carried inside the sealed envelope: the
        // facade must not learn the session's lifetime any more than its secret.
        const Key replyKey = Key::generateSealing();
        const nlohmann::json inner = {
            {"secret", toBase64(secret)},
            {"replyKey", toBase64(replyKey.publicDer())},
        };
        const std::string innerText = inner.dump();
        const Key servingKey = Key::fromPublicDer(sessionSealingKeyDer_);
        const nlohmann::json body = {{"sealed",
            toBase64(cms::seal(Bytes(innerText.begin(), innerText.end()), servingKey))}};
        const std::string text = body.dump();
        const auth::Headers signed_ = auth::signRequest(identity_, now, "POST",
            "/v1/auth/session", Bytes(text.begin(), text.end()));
        std::map<std::string, std::string> headers(signed_.begin(), signed_.end());
        headers.emplace("X-Bazarish-Client", clientId_);
        const ApiResponse response
            = transmitLocked("POST", "/v1/auth/session", {}, Bytes(text.begin(), text.end()),
                "application/json", headers, kDefaultReadTimeoutSeconds, false);
        const nlohmann::json reply = response.json();
        const Bytes opened
            = cms::unseal(fromBase64(reply.at("sealed").get<std::string>()), replyKey);
        const nlohmann::json answer = nlohmann::json::parse(opened.begin(), opened.end());
        // The id never travels: both sides derive it, and what goes on the wire
        // is a different handle per request.
        sessionSecret_ = secret;
        sessionId_ = toHex(sha256(secret)).substr(0, kSessionIdChars);
        sessionKey_ = auth::deriveSessionKey(secret, sessionId_);
        sessionUntil_ = answer.at("expiresUnix").get<std::int64_t>();
        sessionSeq_ = 0;
        sessionRefusals_ = 0;
        bazarish::log::info("session open for {} s", sessionUntil_ - now);
        return true;
    } catch (const std::exception& error) {
        // Anything at all: no session face, no destination yet, a refusal. Keep
        // signing, and do not ask again for a while.
        sessionId_.clear();
        sessionBlockedUntil_ = now + kBlockedForSeconds;
        bazarish::log::info("no session, signing each request: {}", error.what());
        return false;
    }
}

void ApiClient::setSessionSealingKey(Bytes servingSealingKeyDer)
{
    const std::lock_guard<std::mutex> lock(netMutex_);
    if (servingSealingKeyDer == sessionSealingKeyDer_) {
        return;
    }
    // A different serving key means a different destination: the old session was
    // opened against something that no longer applies.
    sessionSealingKeyDer_ = std::move(servingSealingKeyDer);
    sessionId_.clear();
    sessionBlockedUntil_ = 0;
}

void ApiClient::setDestinationOwner(std::string owner)
{
    destinationOwner_ = std::move(owner);
}

void ApiClient::releaseI2pLink()
{
    const std::lock_guard<std::mutex> lock(netMutex_);
    i2pStream_.reset();
    i2pOut_.reset();
}

std::string ApiClient::activeFacadeUrl() const
{
    if (endpoint_.facades.empty()) {
        return {};
    }
    const std::size_t index = activeFacade_ < endpoint_.facades.size() ? activeFacade_ : 0;
    return facadeToUrl(endpoint_.facades[index]);
}

std::optional<ApiResponse> ApiClient::i2pExchange(const Facade& facade, const std::string& method,
    const std::string& fullPath, const std::map<std::string, std::string>& headers,
    const std::size_t bodyLen, const std::function<void(bazarish::i2p::Stream&)>& writeBody)
{
    reportConnectProgress(30, "Starting the I2P router");
    sharedI2pRouter(i2pDataDir_);  // started here if it is not up yet
    if (!i2pOut_) {
        reportConnectProgress(40, "Building your I2P tunnels");
        // One destination per account, shared with everything else that dials its
        // facade: streams multiplex over it, so a second one would only mean a
        // second set of tunnels.
        i2pOut_ = facadeLinkFor(destinationOwner_, tunnelPrivacy());
        if (!i2pOut_) {
            return std::nullopt;  // no router yet: the caller falls back or retries
        }
    }
    // A dial from a destination whose tunnels are still building fails for a
    // reason that has nothing to do with the facade, and would be reported as an
    // unreachable one. Wait for our own side first; only then is a failure the
    // facade's.
    if (!i2pOut_->waitReady(std::chrono::seconds(kOutboundReadySeconds))) {
        reportConnectProgress(40, "I2P tunnels are still building");
        return std::nullopt;
    }
    // The connection is kept between requests. A destination carries the stream's
    // tunnels; what a fresh stream costs is its own opening bytes (the identity
    // and signature ride the first packet) and a socket the facade opens for it,
    // not a round trip - the request travels on the very packet that opens the
    // stream. Reusing it saves that per-request weight, and stops each request
    // being a connection of its own to anyone counting them.
    for (int attempt = 0; attempt < kKeepAliveAttempts; ++attempt) {
        const bool reused = static_cast<bool>(i2pStream_);
        if (!reused) {
            reportConnectProgress(55, "Looking up the server's I2P address");
            i2pStream_ = i2pOut_->connect(facade.host, std::chrono::seconds(kFacadeDialSeconds));
            if (!i2pStream_) {
                return std::nullopt;  // facade unreachable - try the next
            }
        }
        reportConnectProgress(65, "Connected to the server over I2P");
        try {
            const std::string head = buildI2pHttpRequest(
                method, facade.host, fullPath, headers, bodyLen, /*keepAlive=*/true);
            i2pStream_->writeAll(head.data(), head.size());
            if (bodyLen > 0 && writeBody) {
                writeBody(*i2pStream_);
            }
            const bazarish::I2pHttpResponse parsed = readI2pHttpResponse(*i2pStream_);
            if (const auto it = parsed.headers.find("connection");
                it != parsed.headers.end() && it->second.find("close") != std::string::npos) {
                i2pStream_.reset();  // the server is done with this one
            }
            ApiResponse response;
            response.status = parsed.status;
            response.body = Bytes(parsed.body.begin(), parsed.body.end());
            if (const auto it = parsed.headers.find("content-type"); it != parsed.headers.end()) {
                response.contentType = it->second;
            }
            response.headers = parsed.headers;  // already lowercased by the parser
            return response;
        } catch (const std::exception& error) {
            i2pStream_.reset();
            // A connection the server had already closed fails on its next use, and
            // that is not the facade misbehaving: dial again and ask once more.
            // Both body writers replay from their source, so the repeat is whole.
            if (reused) {
                bazarish::log::info("kept connection was already closed; dialling again");
                continue;
            }
            bazarish::log::warn("i2p facade {} answered unframed: {}",
                facade.host.substr(0, 12), error.what());
            throw;
        }
    }
    return std::nullopt;
}

ApiResponse ApiClient::get(const std::string& path, const std::string& query)
{
    return send("GET", path, query, {}, {}, true);
}

ApiResponse ApiClient::getWaiting(
    const std::string& path, const std::string& query, const int readTimeoutSeconds)
{
    return send("GET", path, query, {}, {}, true, {}, readTimeoutSeconds);
}

ApiResponse ApiClient::postJson(
    const std::string& path, const nlohmann::json& body, const int readTimeoutSeconds)
{
    const std::string text = body.dump();
    return send("POST", path, {}, Bytes(text.begin(), text.end()), "application/json", true, {},
        readTimeoutSeconds);
}

ApiResponse ApiClient::postBytes(
    const std::string& path, const Bytes& body, const std::string& contentType)
{
    return send("POST", path, {}, body, contentType, true);
}

ApiResponse ApiClient::putBytes(const std::string& path, const Bytes& body,
    const std::string& contentType, const std::map<std::string, std::string>& extraHeaders)
{
    return send("PUT", path, {}, body, contentType, true, extraHeaders);
}

ApiResponse ApiClient::del(const std::string& path, const nlohmann::json& body)
{
    Bytes encoded;
    std::string contentType;
    if (!body.is_null()) {
        const std::string text = body.dump();
        encoded.assign(text.begin(), text.end());
        contentType = "application/json";
    }
    return send("DELETE", path, {}, encoded, contentType, true);
}

ApiResponse ApiClient::getPublic(const std::string& path, const std::string& query)
{
    return send("GET", path, query, {}, {}, false);
}

ApiResponse ApiClient::getClearnet(const std::string& path, const std::string& query)
{
    return send("GET", path, query, {}, {}, false, {}, kDefaultReadTimeoutSeconds, true);
}

namespace {

std::vector<Bytes> routersFromReseedBody(const nlohmann::json& body)
{
    std::vector<Bytes> routers;
    for (const nlohmann::json& entry : body.at("routers")) {
        routers.push_back(fromBase64(entry.get<std::string>()));
    }
    return routers;
}

}  // namespace

void ApiClient::seedRouterFromServer()
{
    if (i2pDataDir_.empty() || !i2pEnabled()) {
        return;  // no embedded transport to bootstrap
    }
    const bool seeded = seedRouterOnce(i2pDataDir_, [this]() {
        reportConnectProgress(10, "Asking your server for the I2P network database");
        try {
            // Clearnet by construction: this call bootstraps the transport itself.
            return routersFromReseedBody(getClearnet("/v1/messaging/reseed").json());
        } catch (const std::exception& error) {
            bazarish::log::info("own server did not reseed: {}", error.what());
        }
        // Every other server this application holds an account with, in turn:
        // bootstrapping is the application's job, not one account's, and a
        // client with three accounts has three places to ask before it reaches
        // outside. Started at a rotating position so one unreachable facade is
        // not always the first thing tried.
        const std::vector<std::string> facades = reseedFacades();
        static std::atomic<std::size_t> nextFacade{0};
        for (std::size_t i = 0; i < facades.size(); ++i) {
            const std::string& url = facades[(nextFacade + i) % facades.size()];
            try {
                const Facade facade = parseFacadeUrl(url);
                if (facadeIsI2p(facade)) {
                    continue;  // an I2P facade cannot be reached before I2P is up
                }
                reportConnectProgress(15, "Asking another of your servers for the network database");
                bazarish::http::ClientRequest ask;
                ask.method = "GET";
                ask.target = facade.basePath + "/v1/messaging/reseed";
                const bazarish::http::ClientResponse res
                    = bazarish::http::request(facade.host, facade.port, ask, {});
                if (res.status != 200) {
                    continue;
                }
                std::vector<Bytes> routers = routersFromReseedBody(nlohmann::json::parse(res.body));
                if (!routers.empty()) {
                    ++nextFacade;
                    return routers;
                }
            } catch (const std::exception& error) {
                bazarish::log::info("reseed from {} failed: {}", url, error.what());
            }
        }
        ++nextFacade;
        return std::vector<Bytes>{};
    });
    // i2pd's own reseed hosts are the last resort, and only when there is nobody
    // to ask: no clearnet facade in this server's descriptor, or none answered.
    // Otherwise the bootstrap stays between the user and their own server.
    if (seeded) {
        reportConnectProgress(25, "Network database ready");
    }
    if (!seeded) {
        const bool haveClearnetFacade = std::any_of(endpoint_.facades.begin(),
            endpoint_.facades.end(), [](const Facade& f) { return !facadeIsI2p(f); });
        setPublicReseedAllowed(true);
        reportConnectProgress(25, "Your server did not answer: bootstrapping from public reseeds");
        // Said where the user can see it, not only in a log: this is the one
        // moment the client reaches outside the network they chose, and it is
        // their call whether that is acceptable.
        reportBootstrapNotice(haveClearnetFacade
                ? "Your server did not answer with an I2P network database, so this client is "
                  "bootstrapping I2P from public reseed hosts."
                : "This server publishes no clearnet address to bootstrap from, so this client "
                  "is bootstrapping I2P from public reseed hosts.");
        if (haveClearnetFacade) {
            bazarish::log::warn(
                "no clearnet facade answered the reseed: falling back to public reseed hosts");
        } else {
            bazarish::log::warn(
                "this server publishes no clearnet facade: falling back to public reseed hosts");
        }
    }
}

void ApiClient::setWireLog(WireLog* const log)
{
    wireLog_ = log;
}

void ApiClient::noteWire(const std::string& method, const std::string& path,
    const std::string& status, const std::size_t bytes, const std::int64_t elapsedMillis)
{
    if (wireLog_ == nullptr) {
        return;
    }
    WireEvent event;
    event.outgoing = true;
    event.what = method + " " + path;
    event.status = status;
    event.detail = std::to_string(bytes) + " B - " + std::to_string(elapsedMillis) + " ms";
    wireLog_->record(std::move(event));
}

ApiResponse ApiClient::send(const std::string& method, const std::string& path,
    const std::string& query, const Bytes& body, const std::string& contentType,
    const bool authenticate, const std::map<std::string, std::string>& extraHeaders,
    const int readTimeoutSeconds, const bool clearnetOnly)
{
    // Before the request lock: a call that may go over I2P must not start the
    // router unseeded. A clearnet-only call skips it - it cannot start the
    // router, and the seeding fetch is itself one of those.
    if (!clearnetOnly) {
        seedRouterFromServer();
    }
    const std::lock_guard<std::mutex> lock(netMutex_);
    // The signed canonical path is the server-visible path: no base path and
    // no query string (the facade strips the base path before forwarding and
    // the server verifies the query-less path). The signature is therefore the
    // same across facades, so it is computed once.
    // A session is held with the messaging server, which issued it against a key
    // only it has. The service node behind /v1/account/* never saw that exchange,
    // so those calls keep presenting the signature.
    const bool sessionRoute = path.rfind("/v1/messaging/", 0) == 0;
    std::map<std::string, std::string> headers;
    if (authenticate) {
        // A session MAC when we hold one, the full hybrid signature otherwise -
        // which is also what opens the session in the first place.
        auth::Headers authHeaders;
        if (sessionRoute && ensureSessionLocked()) {
            const std::uint64_t seq = ++sessionSeq_;
            authHeaders = auth::macRequest(auth::sessionHandle(sessionSecret_, seq), sessionKey_,
                seq, nowSeconds(), method, path, body);
        } else {
            authHeaders = auth::signRequest(identity_, nowSeconds(), method, path, body);
        }
        headers = std::map<std::string, std::string>(authHeaders.begin(), authHeaders.end());
        headers.emplace("X-Bazarish-Client", clientId_);
    }
    // Extra headers ride outside the signature (e.g. blob retention, which is
    // not integrity-critical - end-to-end integrity is the sealed pointer's
    // sha256).
    for (const auto& [key, value] : extraHeaders) {
        headers.emplace(key, value);
    }
    // A poll that waited and brought nothing back would be the only thing this
    // log ever showed, so on success it is left to its caller, which knows
    // whether anything came. A poll that failed is recorded here like any other.
    const bool quietOnSuccess = path == kEventsPath;
    const auto startedAt = std::chrono::steady_clock::now();
    const auto elapsedMillis = [&startedAt]() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startedAt)
            .count();
    };
    try {
        const ApiResponse response = transmitLocked(
            method, path, query, body, contentType, headers, readTimeoutSeconds, clearnetOnly);
        if (!quietOnSuccess) {
            noteWire(method, path, std::to_string(response.status), response.body.size(),
                elapsedMillis());
        }
        return response;
    } catch (const ApiError& error) {
        // A refused session is answered by opening a new one and trying once
        // more, with a signature this time - never by retrying the same way,
        // which is how a server stuck on 401 would spin a client forever.
        if (error.code != ErrorCode::eSessionInvalid || sessionId_.empty() || !sessionRoute) {
            noteWire(method, path, "failed: " + std::string(error.what()), 0, elapsedMillis());
            throw;
        }
        constexpr int kRefusalsBeforeGivingUp = 3;
        constexpr std::int64_t kBlockedAfterRefusalsSeconds = 900;
        bazarish::log::info("session refused mid-request; signing this one");
        sessionId_.clear();
        if (++sessionRefusals_ >= kRefusalsBeforeGivingUp) {
            sessionRefusals_ = 0;
            sessionBlockedUntil_ = nowSeconds() + kBlockedAfterRefusalsSeconds;
            bazarish::log::warn("sessions keep being refused; signing every request for now");
        }
        const auth::Headers signedHeaders
            = auth::signRequest(identity_, nowSeconds(), method, path, body);
        std::map<std::string, std::string> retryHeaders(
            signedHeaders.begin(), signedHeaders.end());
        retryHeaders.emplace("X-Bazarish-Client", clientId_);
        for (const auto& [key, value] : extraHeaders) {
            retryHeaders.emplace(key, value);
        }
        const ApiResponse response = transmitLocked(method, path, query, body, contentType,
            retryHeaders, readTimeoutSeconds, clearnetOnly);
        if (!quietOnSuccess) {
            noteWire(method, path, std::to_string(response.status), response.body.size(),
                elapsedMillis());
        }
        return response;
    }
}

ApiResponse ApiClient::transmitLocked(const std::string& method, const std::string& path,
    const std::string& query, const Bytes& body, const std::string& contentType,
    const std::map<std::string, std::string>& headerMap, const int readTimeoutSeconds,
    const bool clearnetOnly)
{
    // The headers the I2P transport writes verbatim (Host / Content-Length /
    // Connection are added by the builder); the clearnet leg sends the same set.
    std::map<std::string, std::string> i2pHeaders = headerMap;
    if (!body.empty() && !contentType.empty()) {
        i2pHeaders["Content-Type"] = contentType;
    }

    // Issues the request against one clearnet facade. A send may relay over I2P
    // synchronously on the server side (tens of seconds), so the timeouts are
    // generous. An empty result means the facade was unreachable.
    const auto clearnetAttempt = [&](const Facade& facade) -> bazarish::http::ClientResponse {
        if (method != "GET" && method != "POST" && method != "PUT" && method != "DELETE") {
            throw ApiError(std::nullopt, 0, "unsupported HTTP method: " + method);
        }
        bazarish::http::ClientRequest out;
        out.method = method;
        out.target = facade.basePath + path;
        if (!query.empty()) {
            out.target += "?" + query;
        }
        out.headers = headerMap;
        out.body = std::string(body.begin(), body.end());
        if (!body.empty()) {
            out.contentType = contentType;
        }
        return bazarish::http::request(
            facade.host, facade.port, out, facadeOptions(facade, readTimeoutSeconds));
    };

    // The API goes to the facades, in order, failing over only when one is
    // unreachable; a facade that answers with an error is final (no failover) and
    // the caller's retry loop re-enters here. A clearnet-only request is the
    // reseed, and it goes to the reseed addresses instead - they are a different
    // list precisely because they serve a different purpose.
    const std::vector<Facade>& facades
        = clearnetOnly && !endpoint_.reseeds.empty() ? endpoint_.reseeds : endpoint_.facades;
    std::vector<std::size_t> attempts;
    if (&facades == &endpoint_.reseeds) {
        attempts.resize(facades.size());
        for (std::size_t i = 0; i < facades.size(); ++i) {
            attempts[i] = i;
        }
    } else {
        attempts = facadeOrder();
    }
    std::string lastError = "no facade configured";
    for (const std::size_t index : attempts) {
        const Facade& facade = facades[index];

        if (facadeIsI2p(facade)) {
            if (clearnetOnly) {
                // The caller bootstraps the I2P transport itself; it cannot use it.
                lastError = "clearnet-only request: " + facade.host;
                continue;
            }
            if (!i2pEnabled()) {
                // I2P turned off in settings: use clearnet facades only. With no
                // reachable clearnet facade the loop ends in an explicit error.
                lastError = "i2p is turned off (clearnet only): " + facade.host;
                continue;
            }
            if (i2pDataDir_.empty()) {
                lastError = "i2p facade without an I2P transport: " + facade.host;
                continue;
            }
            std::string fullPath = facade.basePath + path;
            if (!query.empty()) {
                fullPath += "?" + query;
            }
            const std::optional<ApiResponse> response
                = i2pExchange(facade, method, fullPath, i2pHeaders, body.size(),
                    [&body](bazarish::i2p::Stream& stream) {
                        stream.writeAll(body.data(), body.size());
                    });
            if (!response) {
                lastError = "i2p facade unreachable: " + facade.host;
                continue;
            }
            activeFacade_ = index;
            if (response->status < 200 || response->status >= 300) {
                raiseFromResponse(response->status, response->body);
            }
            return *response;
        }

        // Only two things reach a clearnet address: the reseed, which carries no
        // identity and is what makes I2P possible at all, and everything at all
        // when a stand is being talked to without I2P on purpose.
        if (!clearnetOnly && !bazarish::allowFacadeWithoutI2pForDevPurposes()
            && !facadeIsOwnLoopback(facade)) {
            lastError = "this client speaks to its server over I2P only: " + facade.host;
            continue;
        }
        const bazarish::http::ClientResponse result = clearnetAttempt(facade);
        if (result.status == 0) {
            // A read timeout is not an unreachable facade: the request arrived and
            // the server is still working on it (a federated fetch dials the peer
            // over I2P, which is slow on a cold router). Say which of the two it
            // was, or the next reader goes looking at the facade for nothing.
            lastError = result.readTimedOut
                ? "no response within " + std::to_string(readTimeoutSeconds)
                    + "s: " + facade.host
                : "transport failure: " + result.error;
            continue;  // try the next facade
        }
        activeFacade_ = index;  // remember the working facade for next time

        ApiResponse response;
        response.status = result.status;
        response.body = Bytes(result.body.begin(), result.body.end());
        response.contentType = result.contentType;
        response.headers = result.headers;  // the client lowercases the keys
        if (response.status < 200 || response.status >= 300) {
            raiseFromResponse(response.status, response.body);
        }
        return response;
    }
    throw ApiError(std::nullopt, 0, "no facade answered: " + lastError);
}

ApiResponse ApiClient::putFile(const std::string& path, const std::filesystem::path& filePath,
    const std::string& bodySha256Hex, const std::string& contentType,
    const std::map<std::string, std::string>& extraHeaders, const UploadProgressFn& onProgress)
{
    // Before the request lock: a call that may go over I2P must not start the
    // router unseeded, and the seeding is itself a (clearnet) request.
    seedRouterFromServer();
    const std::lock_guard<std::mutex> lock(netMutex_);
    const std::uintmax_t length = std::filesystem::file_size(filePath);

    // The body is signed only through its digest, so a multi-gigabyte file is
    // never materialized to sign or send it.
    const auth::Headers signedHeaders
        = auth::signRequestDigest(identity_, nowSeconds(), "PUT", path, bodySha256Hex);
    std::map<std::string, std::string> headers(signedHeaders.begin(), signedHeaders.end());
    headers["X-Bazarish-Client"] = clientId_;
    for (const auto& [key, value] : extraHeaders) {
        headers[key] = value;
    }

    std::map<std::string, std::string> i2pHeaders = headers;
    if (!contentType.empty()) {
        i2pHeaders["Content-Type"] = contentType;
    }

    const auto clearnetAttempt = [&](const Facade& facade) -> bazarish::http::ClientResponse {
        // A fresh stream per attempt so a facade failover restarts cleanly from
        // the beginning of the file.
        const auto file = std::make_shared<std::ifstream>(filePath, std::ios::binary);
        if (!*file) {
            throw ApiError(std::nullopt, 0, "cannot open blob file: " + filePath.string());
        }
        const auto produced = std::make_shared<std::uintmax_t>(0);
        const bazarish::http::BodyProvider provider
            = [file, produced, length, &onProgress](
                  char* const chunk, const std::size_t capacity) -> std::size_t {
            file->read(chunk, static_cast<std::streamsize>(capacity));
            const std::streamsize got = file->gcount();
            if (got <= 0) {
                return 0;
            }
            *produced += static_cast<std::uintmax_t>(got);
            if (onProgress) {
                onProgress(*produced, static_cast<std::uint64_t>(length));
            }
            return static_cast<std::size_t>(got);
        };
        bazarish::http::ClientRequest out;
        out.method = "PUT";
        out.target = facade.basePath + path;
        out.headers = headers;
        out.contentType = contentType;
        return bazarish::http::upload(facade.host, facade.port, out, length, provider,
            facadeOptions(facade, kDefaultReadTimeoutSeconds));
    };

    // Streams the file body onto an I2P stream after the request head (the i2p
    // counterpart of the clearnet content provider).
    const auto writeFileBody = [&filePath, length](bazarish::i2p::Stream& stream) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            throw ApiError(std::nullopt, 0, "cannot open blob file: " + filePath.string());
        }
        std::array<char, 64 * 1024> buffer;
        std::uintmax_t remaining = length;
        while (remaining > 0) {
            const std::streamsize chunk = static_cast<std::streamsize>(
                std::min<std::uintmax_t>(remaining, buffer.size()));
            file.read(buffer.data(), chunk);
            const std::streamsize got = file.gcount();
            if (got <= 0) {
                break;
            }
            stream.writeAll(buffer.data(), static_cast<std::size_t>(got));
            remaining -= static_cast<std::uintmax_t>(got);
        }
    };

    const std::vector<Facade>& facades = endpoint_.facades;
    std::string lastError = "no facade configured";
    for (const std::size_t index : facadeOrder()) {
        const Facade& facade = facades[index];

        if (facadeIsI2p(facade)) {
            if (!i2pEnabled()) {
                // I2P turned off in settings: use clearnet facades only. With no
                // reachable clearnet facade the loop ends in an explicit error.
                lastError = "i2p is turned off (clearnet only): " + facade.host;
                continue;
            }
            if (i2pDataDir_.empty()) {
                lastError = "i2p facade without an I2P transport: " + facade.host;
                continue;
            }
            const std::optional<ApiResponse> response = i2pExchange(facade, "PUT",
                facade.basePath + path, i2pHeaders, static_cast<std::size_t>(length), writeFileBody);
            if (!response) {
                lastError = "i2p facade unreachable: " + facade.host;
                continue;
            }
            activeFacade_ = index;
            if (response->status < 200 || response->status >= 300) {
                raiseFromResponse(response->status, response->body);
            }
            return *response;
        }

        if (!bazarish::allowFacadeWithoutI2pForDevPurposes() && !facadeIsOwnLoopback(facade)) {
            lastError = "this client speaks to its server over I2P only: " + facade.host;
            continue;
        }
        const bazarish::http::ClientResponse result = clearnetAttempt(facade);
        if (result.status == 0) {
            // A read timeout is not an unreachable facade: the request arrived and
            // the server is still working on it (a federated fetch dials the peer
            // over I2P, which is slow on a cold router). Say which of the two it
            // was, or the next reader goes looking at the facade for nothing.
            lastError = result.readTimedOut
                ? "no response within " + std::to_string(kDefaultReadTimeoutSeconds)
                    + "s: " + facade.host
                : "transport failure: " + result.error;
            continue;  // try the next facade
        }
        activeFacade_ = index;

        ApiResponse response;
        response.status = result.status;
        response.body = Bytes(result.body.begin(), result.body.end());
        response.contentType = result.contentType;
        response.headers = result.headers;  // the client lowercases the keys
        if (response.status < 200 || response.status >= 300) {
            raiseFromResponse(response.status, response.body);
        }
        return response;
    }
    throw ApiError(std::nullopt, 0, "no facade answered: " + lastError);
}

}  // namespace bazarish::client
