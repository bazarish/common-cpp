// Bazarish project (c) 2026
#include "ApiClient.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Tunnel.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/I2pHttp.hpp>
#include <bazarish/Limits.hpp>

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

constexpr int kKeepAliveAttempts = 2;
constexpr int kOutboundReadySeconds = 180;
constexpr int kFacadeDialSeconds = 60;
constexpr auto kKeptStreamIdleSeconds = std::chrono::seconds(60);
constexpr std::size_t kSessionSecretBytes = 32;
constexpr std::size_t kSessionIdChars = 32;

[[noreturn]] void raiseFromResponse(const int status, const Bytes& body)
{
    const std::string text(body.begin(), body.end());
    try {
        const nlohmann::json document = nlohmann::json::parse(text);
        const std::optional<ParsedError> parsed = parseErrorEnvelope(document);
        if (parsed.has_value()) {
            throw ApiError(parsed->code, status,
                parsed->message.empty()
                    ? ("server refused with status " + std::to_string(status))
                    : parsed->message);
        }
    } catch (const nlohmann::json::exception&) {
        // error-hiding: allowed - not an error envelope; the ApiError below carries status and text.
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

bool ApiClient::facadeIsOwnLoopback(const Facade& facade)
{
    if (!bazarish::selfHostedFacadeOnLoopback()) {
        return false;
    }
    return facade.host == "127.0.0.1" || facade.host == "::1";
}

std::vector<std::size_t> ApiClient::facadeOrder() const
{
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

std::int64_t ApiClient::sessionBackoffSeconds(const int httpStatus)
{
    constexpr std::int64_t kAfterRefusalSeconds = 900;
    constexpr std::int64_t kAfterSilenceSeconds = 60;
    return httpStatus == 0 ? kAfterSilenceSeconds : kAfterRefusalSeconds;
}

void ApiClient::ensureServerKeyLocked()
{
    if (!serverSealingKeyDer_.empty()) {
        return;
    }
    const ApiResponse response = transmitLocked("GET",
        std::string(bazarish::tunnel::kServerCardPath), {}, {}, {}, {},
        kDefaultReadTimeoutSeconds);
    const ServerCard card = ServerCard::verify(response.body);
    if (!endpoint_.serverFingerprint.empty() && card.server != endpoint_.serverFingerprint) {
        throw std::runtime_error("the server card names another server than the one we joined");
    }
    if (!Key::fromPublicDer(card.sealingPublicKeyDer).hasKem()) {
        throw std::runtime_error("this server's sealing key has no post-quantum half, so a"
                                 " tunnel cannot be sealed to it - its key needs replacing");
    }
    serverSealingKeyDer_ = card.sealingPublicKeyDer;
}

bool ApiClient::ensureSessionLocked()
{
    constexpr std::int64_t kRenewLeadSeconds = 300;

    const std::int64_t now = nowSeconds();
    if (!sessionId_.empty() && now + kRenewLeadSeconds < sessionUntil_) {
        return true;
    }
    if (now < sessionBlockedUntil_) {
        return false;
    }
    sessionId_.clear();
    try {
        ensureServerKeyLocked();
        bazarish::tunnel::Hello hello;
        hello.secret = randomBytes(kSessionSecretBytes);
        const Key replyKey = Key::generateSealing();
        hello.replyKeyDer = replyKey.publicDer();
        hello.signature = auth::signRequest(identity_, now, bazarish::tunnel::kHelloMethod,
            bazarish::tunnel::kHelloPath, hello.secret);
        const Bytes frame
            = bazarish::tunnel::sealHello(hello, Key::fromPublicDer(serverSealingKeyDer_));
        const ApiResponse response = transmitLocked("POST",
            std::string(bazarish::tunnel::kTunnelPath), {}, frame, "application/octet-stream", {},
            kDefaultReadTimeoutSeconds);
        const bazarish::tunnel::Welcome welcome
            = bazarish::tunnel::openWelcome(response.body, replyKey);
        sessionSecret_ = hello.secret;
        sessionId_ = toHex(sha256(hello.secret)).substr(0, kSessionIdChars);
        sessionKey_ = auth::deriveSessionKey(hello.secret, sessionId_);
        tunnelKey_ = bazarish::tunnel::deriveTunnelKey(hello.secret, sessionId_);
        sessionUntil_ = welcome.expiresUnix;
        sessionSeq_ = 0;
        sessionRefusals_ = 0;
        bazarish::log::info("tunnel open for {} s", sessionUntil_ - now);
        return true;
    } catch (const ApiError& error) {
        sessionId_.clear();
        sessionBlockedUntil_ = now + sessionBackoffSeconds(error.httpStatus);
        lastTunnelError_ = error.what();
        bazarish::log::info("no tunnel: {}", error.what());
        return false;
    } catch (const std::exception& error) {
        sessionId_.clear();
        sessionBlockedUntil_ = now + sessionBackoffSeconds(1);
        lastTunnelError_ = error.what();
        bazarish::log::info("no tunnel: {}", error.what());
        return false;
    }
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
    const std::size_t bodyLen, const std::function<void(bazarish::i2p::Stream&)>& writeBody,
    const int readTimeoutSeconds)
{
    reportConnectProgress(30, "Starting the I2P router");
    setReseedUrls(endpoint_.reseeds);
    if (bootstrapI2pRouter(i2pDataDir_) == I2pBootstrap::eEmpty) {
        return std::nullopt;
    }
    if (i2pOut_ && i2pOut_->lost()) {
        i2pStream_.reset();
        i2pOut_.reset();
    }
    if (!i2pOut_) {
        reportConnectProgress(40, "Building your I2P tunnels");
        i2pOut_ = facadeLinkFor(destinationOwner_, tunnelPrivacy());
        if (!i2pOut_) {
            return std::nullopt;
        }
    }
    if (!i2pOut_->waitReady(std::chrono::seconds(kOutboundReadySeconds))) {
        reportConnectProgress(40, "I2P tunnels are still building");
        return std::nullopt;
    }
    if (i2pStream_
        && std::chrono::steady_clock::now() - i2pStreamUsedAt_ >= kKeptStreamIdleSeconds) {
        i2pStream_.reset();
    }
    for (int attempt = 0; attempt < kKeepAliveAttempts; ++attempt) {
        const bool reused = static_cast<bool>(i2pStream_);
        if (!reused) {
            reportConnectProgress(55, "Looking up the server's I2P address");
            i2pStream_ = i2pOut_->connect(facade.host, std::chrono::seconds(kFacadeDialSeconds));
            if (!i2pStream_) {
                return std::nullopt;
            }
        }
        reportConnectProgress(65, "Connected to the server over I2P");
        i2pStream_->setReadTimeout(std::chrono::seconds(readTimeoutSeconds));
        const auto askedAt = std::chrono::steady_clock::now();
        i2pStreamUsedAt_ = askedAt;
        try {
            const std::string head = buildI2pHttpRequest(
                method, facade.host, fullPath, headers, bodyLen, /*keepAlive=*/true);
            i2pStream_->writeAll(head.data(), head.size());
            if (bodyLen > 0 && writeBody) {
                writeBody(*i2pStream_);
            }
            const bazarish::I2pHttpResponse parsed
                = readI2pHttpResponse(*i2pStream_, bazarish::kMaxFacadeAnswerBytes);
            if (const auto it = parsed.headers.find("connection");
                it != parsed.headers.end() && it->second.find("close") != std::string::npos) {
                i2pStream_.reset();
            }
            ApiResponse response;
            response.status = parsed.status;
            response.body = Bytes(parsed.body.begin(), parsed.body.end());
            if (const auto it = parsed.headers.find("content-type"); it != parsed.headers.end()) {
                response.contentType = it->second;
            }
            response.headers = parsed.headers;
            i2pStreamUsedAt_ = std::chrono::steady_clock::now();
            return response;
        } catch (const std::exception& error) {
            i2pStream_.reset();
            const bool timedOut = std::chrono::steady_clock::now() - askedAt
                >= std::chrono::seconds(readTimeoutSeconds);
            if (reused && !timedOut) {
                bazarish::log::info("kept connection was already closed; dialling again");
                continue;
            }
            if (timedOut) {
                bazarish::log::warn("i2p facade {} did not answer within {}s: {}",
                    facade.host.substr(0, 12), readTimeoutSeconds, error.what());
                return std::nullopt;
            }
            bazarish::log::warn("i2p facade {} answered unframed: {}",
                facade.host.substr(0, 12), error.what());
            throw ApiError(std::nullopt, 0, error.what());
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

ApiResponse ApiClient::postJson(const std::string& path, const nlohmann::json& body,
    const int readTimeoutSeconds, const std::string& note)
{
    const std::string text = body.dump();
    return send("POST", path, {}, Bytes(text.begin(), text.end()), "application/json", true, {},
        readTimeoutSeconds, note);
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

void ApiClient::setWireLog(WireLog* const log)
{
    wireLog_ = log;
}

void ApiClient::noteWire(const std::string& method, const std::string& path,
    const std::string& note, const std::string& status, const std::size_t bytes,
    const std::int64_t elapsedMillis)
{
    if (wireLog_ == nullptr) {
        return;
    }
    WireEvent event;
    event.outgoing = true;
    event.what = method + " " + path + (note.empty() ? std::string() : " (" + note + ")");
    event.status = status;
    event.detail = std::to_string(bytes) + " B - " + std::to_string(elapsedMillis) + " ms";
    wireLog_->record(std::move(event));
}

ApiResponse ApiClient::tunnelledLocked(const std::string& method, const std::string& path,
    const std::string& query, const Bytes& body, const std::string& contentType,
    const std::map<std::string, std::string>& headers, const int readTimeoutSeconds)
{
    bazarish::tunnel::Request inner;
    inner.method = method;
    inner.path = path;
    inner.query = query;
    inner.headers = headers;
    inner.body = body;
    inner.contentType = contentType;
    const std::uint64_t seq = ++sessionSeq_;
    const Bytes frame = bazarish::tunnel::carry(auth::sessionHandle(sessionSecret_, seq),
        tunnelKey_, bazarish::tunnel::encodeRequest(inner));
    const ApiResponse carried = transmitLocked("POST",
        std::string(bazarish::tunnel::kTunnelPath), {}, frame, "application/octet-stream", {},
        readTimeoutSeconds);
    bazarish::tunnel::Response answered;
    try {
        answered = bazarish::tunnel::decodeResponse(
            bazarish::tunnel::open(carried.body, tunnelKey_));
    } catch (const std::exception&) {
        throw ApiError(ErrorCode::eSessionInvalid, carried.status,
            "the tunnel did not answer under the key it was opened with");
    }
    ApiResponse response;
    response.status = answered.status;
    response.contentType = answered.contentType;
    response.body = answered.body;
    return response;
}

ApiResponse ApiClient::send(const std::string& method, const std::string& path,
    const std::string& query, const Bytes& body, const std::string& contentType,
    const bool authenticate, const std::map<std::string, std::string>& extraHeaders,
    const int readTimeoutSeconds, const std::string& note)
{
    const std::lock_guard<std::mutex> lock(netMutex_);
    std::map<std::string, std::string> headers;
    if (authenticate) {
        auth::Headers authHeaders;
        if (ensureSessionLocked()) {
            const std::uint64_t seq = sessionSeq_ + 1;
            authHeaders = auth::macRequest(auth::sessionHandle(sessionSecret_, seq), sessionKey_,
                seq, nowSeconds(), method, path, body, clientId_);
        } else {
            const std::string reason = lastTunnelError_.empty()
                ? std::string("no tunnel to the server")
                : "no tunnel to the server: " + lastTunnelError_;
            noteWire(method, path, note, "failed: " + reason, 0, 0);
            throw ApiError(std::nullopt, 0, reason);
        }
        headers = std::map<std::string, std::string>(authHeaders.begin(), authHeaders.end());
        headers.emplace("X-Bazarish-Client", clientId_);
    }
    for (const auto& [key, value] : extraHeaders) {
        headers.emplace(key, value);
    }
    const bool quietOnSuccess = path == kEventsPath;
    const auto startedAt = std::chrono::steady_clock::now();
    const auto elapsedMillis = [&startedAt]() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startedAt)
            .count();
    };
    const auto accept = [&](const ApiResponse& response) {
        if (response.status < 200 || response.status >= 300) {
            raiseFromResponse(response.status, response.body);
        }
        if (!quietOnSuccess) {
            noteWire(method, path, note, std::to_string(response.status), response.body.size(),
                elapsedMillis());
        }
    };
    const auto failed = [&](const std::string& why) {
        noteWire(method, path, note, "failed: " + why, 0, elapsedMillis());
    };
    try {
        const ApiResponse response = tunnelledLocked(
            method, path, query, body, contentType, headers, readTimeoutSeconds);
        accept(response);
        return response;
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eSessionInvalid || sessionId_.empty()) {
            failed(error.what());
            throw;
        }
        constexpr int kRefusalsBeforeGivingUp = 3;
        bazarish::log::info("the tunnel was refused mid-request; opening another");
        sessionId_.clear();
        if (++sessionRefusals_ >= kRefusalsBeforeGivingUp) {
            sessionRefusals_ = 0;
            sessionBlockedUntil_ = nowSeconds() + sessionBackoffSeconds(1);
            bazarish::log::warn("tunnels keep being refused; standing off for a while");
            failed(error.what());
            throw;
        }
        if (!ensureSessionLocked()) {
            failed("no tunnel");
            throw;
        }
        const std::uint64_t seq = sessionSeq_ + 1;
        const auth::Headers retryAuth = auth::macRequest(auth::sessionHandle(sessionSecret_, seq),
            sessionKey_, seq, nowSeconds(), method, path, body, clientId_);
        std::map<std::string, std::string> retryHeaders(retryAuth.begin(), retryAuth.end());
        retryHeaders.emplace("X-Bazarish-Client", clientId_);
        for (const auto& [key, value] : extraHeaders) {
            retryHeaders.emplace(key, value);
        }
        const ApiResponse response = tunnelledLocked(
            method, path, query, body, contentType, retryHeaders, readTimeoutSeconds);
        accept(response);
        return response;
    }
}

ApiResponse ApiClient::transmitLocked(const std::string& method, const std::string& path,
    const std::string& query, const Bytes& body, const std::string& contentType,
    const std::map<std::string, std::string>& headerMap, const int readTimeoutSeconds)
{
    std::map<std::string, std::string> i2pHeaders = headerMap;
    if (!body.empty() && !contentType.empty()) {
        i2pHeaders["Content-Type"] = contentType;
    }

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

    const std::vector<Facade>& facades = endpoint_.facades;
    const std::vector<std::size_t> attempts = facadeOrder();
    std::string lastError = "no facade configured";
    for (const std::size_t index : attempts) {
        const Facade& facade = facades[index];

        if (facadeIsI2p(facade)) {
            if (!i2pEnabled()) {
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
                    },
                    readTimeoutSeconds);
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
            lastError = result.readTimedOut
                ? "no response within " + std::to_string(readTimeoutSeconds)
                    + "s: " + facade.host
                : "transport failure: " + result.error;
            continue;
        }
        activeFacade_ = index;

        ApiResponse response;
        response.status = result.status;
        response.body = Bytes(result.body.begin(), result.body.end());
        response.contentType = result.contentType;
        response.headers = result.headers;
        if (response.status < 200 || response.status >= 300) {
            raiseFromResponse(response.status, response.body);
        }
        return response;
    }
    throw ApiError(std::nullopt, 0, "no facade answered: " + lastError);
}

}  // namespace bazarish::client
