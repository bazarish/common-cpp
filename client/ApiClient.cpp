// Bazarish project (c) 2026
#include "ApiClient.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/I2pHttp.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/Tunnel.hpp>

#include <bazarish/HttpClient.hpp>
#include <bazarish/JsonRead.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <ctime>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>

namespace bazarish::client {

namespace {

constexpr int kPlainHttpPort = 80;
constexpr std::size_t kShownHostChars = 12;

// Enough of an address to tell facades apart in a log, not enough to dial one.
std::string shortHost(const std::string& host)
{
    return host.substr(0, kShownHostChars);
}

bazarish::http::ClientOptions facadeOptions(const int readTimeoutSeconds)
{
    bazarish::http::ClientOptions options;
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
// Until the link or the facade's lease set changes, asking again meets the same silence.
constexpr std::int64_t kSilenceStandOffSeconds = 60;

constexpr const char* kServerServicePrefix = "/v1/account/";
constexpr const char* kClosedClient = "the client is closed";

const char* tunnelPathOf(const ServerCard::Service service)
{
    return service == ServerCard::Service::eServerService ? bazarish::tunnel::kNodeTunnelPath
                                                        : bazarish::tunnel::kTunnelPath;
}

const char* cardPathOf(const ServerCard::Service service)
{
    return service == ServerCard::Service::eServerService ? bazarish::tunnel::kNodeCardPath
                                                        : bazarish::tunnel::kServerCardPath;
}

const char* serviceName(const ServerCard::Service service)
{
    return service == ServerCard::Service::eServerService ? "server service" : "messaging server";
}

[[noreturn]] void raiseFromResponse(const int status, const Bytes& body, const LinkFailure failure)
{
    const std::string text(body.begin(), body.end());
    try {
        const nlohmann::json document = parseJson(text);
        const std::optional<ParsedError> parsed = parseErrorEnvelope(document);
        if (parsed.has_value()) {
            throw ApiError(parsed->code, status, failure,
                parsed->message.empty()
                    ? ("server refused with status " + std::to_string(status))
                    : parsed->message);
        }
    } catch (const nlohmann::json::exception&) {
        // error-hiding: allowed - not an error envelope; the ApiError below carries status and text.
    }
    throw ApiError(std::nullopt, status, failure,
        text.empty() ? ("server answered status " + std::to_string(status) + " with no body")
                     : text);
}

}  // namespace

void ApiClient::raiseAnswered(const int status, const Bytes& body, const LinkFailure failure)
{
    try {
        raiseFromResponse(status, body, failure);
    } catch (const ApiError& error) {
        if (error.code == ErrorCode::eDeviceRevoked && !deviceRevoked_.exchange(true)) {
            std::function<void()> tell;
            {
                const std::lock_guard<std::mutex> lock(revokedMutex_);
                tell = tellRevoked_;
            }
            if (tell) {
                tell();
            }
        }
        throw;
    }
}

void ApiClient::onDeviceRevoked(std::function<void()> tell)
{
    const std::lock_guard<std::mutex> lock(revokedMutex_);
    tellRevoked_ = std::move(tell);
}

void ApiClient::onLinkStage(std::function<void(LinkStage)> tell)
{
    const std::lock_guard<std::mutex> lock(stageMutex_);
    tellStage_ = std::move(tell);
}

void ApiClient::reach(LinkAttempt& tried, const LinkStage stage)
{
    tried.reached = stage;
    std::function<void(LinkStage)> tell;
    {
        const std::lock_guard<std::mutex> lock(stageMutex_);
        tell = tellStage_;
    }
    if (tell) {
        tell(stage);
    }
}

Facade parseFacadeAddress(const std::string& address)
{
    if (address.empty()) {
        throw std::runtime_error("empty facade address");
    }
    if (address.find('/') != std::string::npos) {
        throw std::runtime_error("a facade is an address, with no scheme and no path");
    }
    Facade facade;
    const std::string::size_type colon = address.find(':');
    facade.host = address.substr(0, colon);
    if (colon != std::string::npos) {
        try {
            facade.port = std::stoi(address.substr(colon + 1));
        } catch (const std::exception&) {
            throw std::runtime_error("invalid facade port");
        }
        if (facade.port <= 0 || facade.port > kMaxPort) {
            throw std::runtime_error("invalid facade port");
        }
    }
    if (facade.host.empty()) {
        throw std::runtime_error("empty facade host");
    }
    return facade;
}

std::string facadeAddress(const Facade& facade)
{
    return facade.port == 0 ? facade.host : facade.host + ":" + std::to_string(facade.port);
}

nlohmann::json ApiResponse::json() const
{
    return parseJson(body);
}

ApiError::ApiError(const std::optional<ErrorCode> code, const int httpStatus,
    const LinkFailure failure, const std::string& message)
    : LinkError(failure, message)
    , code(code)
    , httpStatus(httpStatus)
{
}

ApiClient::ApiClient(const DeviceCredential& credential, ServerEndpoint endpoint,
    std::filesystem::path i2pDataDir)
    : credential_(credential)
    , endpoint_(std::move(endpoint))
    , i2pDataDir_(std::move(i2pDataDir))
{
    if (const std::vector<std::size_t> order = facadeOrder(); !order.empty()) {
        activeFacade_ = order.front();
    }
}

bool ApiClient::facadeIsI2p(const Facade& facade)
{
    return isB32I2pHost(facade.host);
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
    std::vector<std::size_t> order;
    order.reserve(endpoint_.facades.size());
    for (std::size_t i = 0; i < endpoint_.facades.size(); ++i) {
        if (facadeIsI2p(endpoint_.facades[i]) || facadeIsOwnLoopback(endpoint_.facades[i])) {
            order.push_back(i);
        }
    }
    const auto lastAnswered = std::find(order.begin(), order.end(), activeFacade_);
    if (lastAnswered != order.end()) {
        std::rotate(order.begin(), lastAnswered, order.end());
    }
    return order;
}

const ServerEndpoint& ApiClient::endpoint() const
{
    return endpoint_;
}

ApiClient::Tunnel& ApiClient::tunnelFor(const std::string& path)
{
    return path.starts_with(kServerServicePrefix) ? serverService_ : messaging_;
}

void ApiClient::ensureSealingKeyLocked(Tunnel& tunnel)
{
    if (!tunnel.sealingKeyDer.empty()) {
        return;
    }
    requireFingerprint(endpoint_.serverFingerprint);
    const ApiResponse response
        = transmitLocked("GET", cardPathOf(tunnel.service), {}, {}, kDefaultReadTimeoutSeconds);
    const ServerCard card = [&]() {
        try {
            return ServerCard::verify(response.body, tunnel.service);
        } catch (const std::exception& error) {
            linkFailure_.store(LinkFailure::eServerMalformed);
            throw LinkError(LinkFailure::eServerMalformed, error.what());
        }
    }();
    if (card.server != endpoint_.serverFingerprint) {
        linkFailure_.store(LinkFailure::eServerMalformed);
        throw LinkError(LinkFailure::eServerMalformed,
            "the server card names another server than the one we joined");
    }
    tunnel.sealingKeyDer = card.sealingPublicKeyDer;
}

bool ApiClient::ensureSessionLocked(Tunnel& tunnel)
{
    constexpr std::int64_t kRenewLeadSeconds = 300;

    const std::int64_t now = nowSeconds();
    if (!tunnel.sessionId.empty() && now + kRenewLeadSeconds < tunnel.sessionUntil) {
        return true;
    }
    // A wait belongs to the link that failed; one that has come back since is tried at once.
    if (now < tunnel.blockedUntil && tunnel.blockedAtCarry == bazarish::i2p::carryReturns()) {
        return false;
    }
    tunnel.sessionId.clear();
    try {
        ensureSealingKeyLocked(tunnel);
        bazarish::tunnel::Hello hello;
        hello.secret = SecretBytes(randomBytes(kSessionSecretBytes));
        const Key replyKey = Key::generateSealing();
        hello.replyKeyDer = replyKey.publicDer();
        hello.signature = auth::signDeviceRequest(credential_, now, bazarish::tunnel::kHelloMethod,
            bazarish::tunnel::kHelloPath,
            bazarish::tunnel::helloSigned(hello.secret, endpoint_.serverFingerprint).bytes());
        const Bytes frame
            = bazarish::tunnel::sealHello(hello, Key::fromPublicDer(tunnel.sealingKeyDer));
        const ApiResponse response = transmitLocked("POST", tunnelPathOf(tunnel.service), frame,
            "application/octet-stream", kDefaultReadTimeoutSeconds);
        bazarish::tunnel::Welcome welcome;
        try {
            welcome = bazarish::tunnel::openWelcome(response.body, replyKey);
        } catch (const std::exception&) {
            // A server refuses a hello with noise, so nothing tells why.
            linkFailure_.store(LinkFailure::eServerRefused);
            tunnel.lastError = "the server refused the tunnel";
            tunnel.lastFailure = LinkFailure::eServerRefused;
            bazarish::log::info("no tunnel to the {}: {}", serviceName(tunnel.service),
                tunnel.lastError);
            return false;
        }
        const std::string sessionId
            = toHex(sha256(hello.secret.bytes())).substr(0, kSessionIdChars);
        tunnel.sessionKey = auth::deriveSessionKey(hello.secret, sessionId);
        tunnel.tunnelKey = bazarish::tunnel::deriveTunnelKey(hello.secret, sessionId);
        tunnel.sessionSecret = std::move(hello.secret);
        tunnel.sessionUntil = welcome.expiresUnix;
        tunnel.sessionSeq = 0;
        tunnel.sessionId = sessionId;
        bazarish::log::info("tunnel to the {} open for {} s", serviceName(tunnel.service),
            tunnel.sessionUntil - now);
        return true;
    } catch (const ApiError& error) {
        // Any answer, a status or one that does not read, is what the next ask hears too.
        if (error.httpStatus == 0 && error.failure != LinkFailure::eServerMalformed) {
            standOffAfterSilenceLocked(tunnel);
        }
        tunnel.lastError = error.what();
        tunnel.lastFailure = error.failure;
        bazarish::log::info("no tunnel to the {}: {}", serviceName(tunnel.service), error.what());
        return false;
    } catch (const bazarish::i2p::GatewayRefusal& error) {
        tunnel.lastError = error.what();
        tunnel.lastFailure = LinkFailure::eGatewayRefused;
        bazarish::log::warn("no tunnel to the {}: {}", serviceName(tunnel.service), error.what());
        return false;
    }
}

void ApiClient::standOffAfterSilenceLocked(Tunnel& tunnel)
{
    tunnel.blockedUntil = nowSeconds() + kSilenceStandOffSeconds;
    tunnel.blockedAtCarry = bazarish::i2p::carryReturns();
}

void ApiClient::setAccountLabel(std::string accountLabel)
{
    accountLabel_ = std::move(accountLabel);
}

void ApiClient::releaseI2pLink()
{
    std::shared_ptr<bazarish::i2p::Endpoint> link;
    {
        const std::lock_guard<std::mutex> lock(linkMutex_);
        link = link_.lock();
    }
    if (link) {
        link->stop();
    }
}

void ApiClient::close()
{
    closed_.store(true);
    releaseI2pLink();
}

std::string ApiClient::gatewayRefusal() const
{
    const std::lock_guard<std::mutex> lock(netMutex_);
    return gatewayRefusal_;
}

bool ApiClient::serverBehindFacadeDown() const
{
    return linkFailure_.load() == LinkFailure::eServerDown;
}

LinkFailure ApiClient::linkFailure() const
{
    return linkFailure_.load();
}

LinkFailure ApiClient::noteLinkFailure(LinkAttempt attempt)
{
    if (attempt.viaGateway) {
        const auto running = sharedI2pRouterIfRunning();
        attempt.gatewayReady = running.has_value() && running->get().ready();
    }
    const LinkFailure failure = classifyLinkFailure(bazarish::i2p::networkDown(), attempt);
    linkFailure_.store(failure);
    return failure;
}

bool ApiClient::facadePublishedAnew()
{
    const std::lock_guard<std::mutex> lock(netMutex_);
    if (!i2pOut_ || i2pOut_->lost() || i2pOutHost_.empty()) {
        return false;
    }
    const auto running = sharedI2pRouterIfRunning();
    if (!running.has_value() || !running->get().capabilities().leaseSetRefresh) {
        return false;
    }
    bazarish::i2p::LeaseSetRefresh found;
    try {
        found = running->get().refreshLeaseSet(i2pOut_->routingHost(), i2pOutHost_);
    } catch (const std::exception& error) {
        bazarish::log::info("the facade's lease set was not looked up: {}", error.what());
        return false;
    }
    if (!found.after.has_value() || !bazarish::i2p::publishedLater(*found.after, found.before)) {
        return false;
    }
    messaging_.blockedUntil = 0;
    serverService_.blockedUntil = 0;
    return true;
}

void ApiClient::liftStandOff()
{
    const std::lock_guard<std::mutex> lock(netMutex_);
    messaging_.blockedUntil = 0;
    serverService_.blockedUntil = 0;
}

std::string ApiClient::activeFacadeAddress() const
{
    if (endpoint_.facades.empty()) {
        return {};
    }
    const std::size_t index = activeFacade_ < endpoint_.facades.size() ? activeFacade_ : 0;
    return facadeAddress(endpoint_.facades[index]);
}

std::optional<ApiResponse> ApiClient::i2pExchange(const Facade& facade, const std::string& method,
    const std::string& path, const std::map<std::string, std::string>& headers,
    const std::size_t bodyLen, const std::function<void(WatchedStream&)>& writeBody,
    const int readTimeoutSeconds, LinkAttempt& tried)
{
    reach(tried, LinkStage::eRouter);
    reportConnectProgress(credential_.account(), usingGatewayTransport()
            ? ConnectMilestone::eGatewayConnecting
            : ConnectMilestone::eRouterStarting);
    setReseedUrls(endpoint_.reseeds);
    if (bootstrapI2pRouter(i2pDataDir_) == I2pBootstrap::eEmpty) {
        return std::nullopt;
    }
    gatewayRefusal_.clear();
    const auto buildLink = [&]() {
        reach(tried, LinkStage::eLink);
        reportConnectProgress(credential_.account(), ConnectMilestone::eTunnelsBuilding);
        i2pStream_.reset();
        try {
            i2pOut_ = facadeLinkFor(credential_.account(), accountLabel_, tunnelPrivacy(), facade.host);
        } catch (const bazarish::i2p::GatewayRefusal& refusal) {
            gatewayRefusal_ = refusal.what();
            throw;
        }
        i2pOutHost_ = facade.host;
        {
            const std::lock_guard<std::mutex> lock(linkMutex_);
            link_ = i2pOut_;
        }
        if (i2pOut_) {
            reach(tried, LinkStage::eTunnels);
        }
        return static_cast<bool>(i2pOut_);
    };
    if (i2pOut_ && (i2pOut_->lost() || i2pOutHost_ != facade.host)) {
        i2pStream_.reset();
        i2pOut_.reset();
    }
    if (!i2pOut_ && !buildLink()) {
        return std::nullopt;
    }
    reach(tried, LinkStage::eTunnels);
    if (!i2pOut_->waitReady(std::chrono::seconds(kOutboundReadySeconds))) {
        reportConnectProgress(credential_.account(), ConnectMilestone::eTunnelsStillBuilding);
        return std::nullopt;
    }
    reach(tried, LinkStage::eDial);
    if (i2pStream_
        && std::chrono::steady_clock::now() - i2pStreamUsedAt_ >= kKeptStreamIdleSeconds) {
        i2pStream_.reset();
    }
    std::chrono::steady_clock::time_point dialedAt;
    const auto dial = [&]() {
        dialedAt = std::chrono::steady_clock::now();
        i2pStream_ = i2pOut_->connect(facade.host, std::chrono::seconds(kFacadeDialSeconds));
    };
    for (int attempt = 0; attempt < kKeepAliveAttempts; ++attempt) {
        const bool reused = static_cast<bool>(i2pStream_);
        if (!reused) {
            reportConnectProgress(credential_.account(), ConnectMilestone::eServerLookup);
            dial();
            // A gateway that replaced its session under the dial lost the link; no facade refused.
            if (!i2pStream_ && i2pOut_->lost()) {
                if (!buildLink()
                    || !i2pOut_->waitReady(std::chrono::seconds(kOutboundReadySeconds))) {
                    return std::nullopt;
                }
                reach(tried, LinkStage::eDial);
                dial();
            }
            if (!i2pStream_) {
                const auto spent = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - dialedAt);
                // The router gives up a lease set lookup on its own; only a timed-out dial waited.
                tried.dialEndedEarly = spent < std::chrono::seconds(kFacadeDialSeconds);
                if (tried.dialEndedEarly) {
                    bazarish::log::info("facade {}: its address was not found, after {} ms",
                        shortHost(facade.host), spent.count());
                } else {
                    bazarish::log::info("facade {}: no answer in {} s", shortHost(facade.host),
                        kFacadeDialSeconds);
                }
                return std::nullopt;
            }
        }
        reach(tried, LinkStage::eExchange);
        reportConnectProgress(credential_.account(), ConnectMilestone::eServerReached);
        i2pStream_->setReadTimeout(std::chrono::seconds(readTimeoutSeconds));
        const auto askedAt = std::chrono::steady_clock::now();
        i2pStreamUsedAt_ = askedAt;
        WatchedStream watched(*i2pStream_);
        try {
            const std::string head = buildI2pHttpRequest(
                method, facade.host, path, headers, bodyLen, /*keepAlive=*/true);
            watched.writeAll(viewOf(head));
            if (bodyLen > 0 && writeBody) {
                writeBody(watched);
            }
            const bazarish::I2pHttpResponse parsed
                = readI2pHttpResponse(watched, bazarish::kMaxFacadeAnswerBytes);
            if (const auto it = parsed.headers.find("connection");
                it != parsed.headers.end() && it->second.find("close") != std::string::npos) {
                i2pStream_.reset();
            }
            ApiResponse response;
            response.status = parsed.status;
            response.body = Bytes(parsed.body.begin(), parsed.body.end());
            i2pStreamUsedAt_ = std::chrono::steady_clock::now();
            return response;
        } catch (const std::exception& error) {
            i2pStream_.reset();
            if (closed_.load()) {
                throw ApiError(std::nullopt, 0, LinkFailure::eNone, kClosedClient);
            }
            const bool timedOut = readTimeoutSeconds != kNoReadDeadline
                && std::chrono::steady_clock::now() - askedAt
                    >= std::chrono::seconds(readTimeoutSeconds);
            if (reused && !timedOut) {
                bazarish::log::info("kept connection was already closed; dialling again");
                continue;
            }
            if (timedOut) {
                bazarish::log::warn("i2p facade {} did not answer within {}s: {}",
                    shortHost(facade.host), readTimeoutSeconds, error.what());
                return std::nullopt;
            }
            if (watched.failed()) {
                bazarish::log::warn("i2p facade {} gave no whole answer: {}",
                    shortHost(facade.host), error.what());
                return std::nullopt;
            }
            bazarish::log::warn("i2p facade {} answered malformed: {}",
                shortHost(facade.host), error.what());
            tried.malformed = true;
            throw ApiError(std::nullopt, 0, LinkFailure::eServerMalformed, error.what());
        }
    }
    return std::nullopt;
}

ApiResponse ApiClient::get(const std::string& path, const std::string& query)
{
    return send("GET", path, query, {}, {});
}

ApiResponse ApiClient::getWaiting(
    const std::string& path, const std::string& query, const int readTimeoutSeconds)
{
    return send("GET", path, query, {}, {}, readTimeoutSeconds);
}

ApiResponse ApiClient::postJson(const std::string& path, const nlohmann::json& body,
    const int readTimeoutSeconds, const std::string& note)
{
    const std::string text = body.dump();
    return send("POST", path, {}, SecretBytes(Bytes(text.begin(), text.end())), "application/json",
        readTimeoutSeconds, note);
}

ApiResponse ApiClient::postSecret(const std::string& path, const SecretBytes& jsonBody)
{
    return send("POST", path, {}, jsonBody, "application/json");
}

ApiResponse ApiClient::del(const std::string& path, const nlohmann::json& body)
{
    SecretBytes encoded;
    std::string contentType;
    if (!body.is_null()) {
        const std::string text = body.dump();
        encoded = SecretBytes(Bytes(text.begin(), text.end()));
        contentType = "application/json";
    }
    return send("DELETE", path, {}, encoded, contentType);
}

void ApiClient::setWireLog(std::shared_ptr<WireLog> log)
{
    wireLog_ = std::move(log);
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

ApiResponse ApiClient::tunnelledLocked(Tunnel& tunnel, const std::string& method,
    const std::string& path, const std::string& query, const SecretBytes& body,
    const std::string& contentType, const std::map<std::string, std::string>& headers,
    const int readTimeoutSeconds)
{
    bazarish::tunnel::Request inner;
    inner.method = method;
    inner.path = path;
    inner.query = query;
    inner.headers = headers;
    inner.body = body;
    inner.contentType = contentType;
    const std::uint64_t seq = ++tunnel.sessionSeq;
    const std::string handle = auth::sessionHandle(tunnel.sessionSecret, seq);
    const Bytes frame = bazarish::tunnel::carry(handle, tunnel.tunnelKey,
        bazarish::tunnel::Direction::eRequest, bazarish::tunnel::encodeRequest(inner));
    const ApiResponse carried = transmitLocked("POST", tunnelPathOf(tunnel.service), frame,
        "application/octet-stream", readTimeoutSeconds);
    SecretBytes opened;
    try {
        opened = bazarish::tunnel::open(
            carried.body, tunnel.tunnelKey, bazarish::tunnel::Direction::eAnswer, handle);
    } catch (const std::exception&) {
        // A server answers a tunnel it does not hold with noise.
        linkFailure_.store(LinkFailure::eServerRefused);
        throw ApiError(ErrorCode::eSessionInvalid, carried.status, LinkFailure::eServerRefused,
            "the tunnel did not answer under the key it was opened with");
    }
    bazarish::tunnel::Response answered;
    try {
        answered = bazarish::tunnel::decodeResponse(opened);
    } catch (const std::exception& error) {
        linkFailure_.store(LinkFailure::eServerMalformed);
        std::string reason = "the tunnel's answer does not read: ";
        reason += error.what();
        throw ApiError(std::nullopt, 0, LinkFailure::eServerMalformed, reason);
    }
    ApiResponse response;
    response.status = answered.status;
    response.body = answered.body;
    return response;
}

ApiResponse ApiClient::send(const std::string& method, const std::string& path,
    const std::string& query, const SecretBytes& body, const std::string& contentType,
    const int readTimeoutSeconds, const std::string& note)
{
    if (closed_.load()) {
        throw ApiError(std::nullopt, 0, LinkFailure::eNone, kClosedClient);
    }
    if (bazarish::i2p::networkDown()) {
        linkFailure_.store(LinkFailure::eNoNetwork);
        noteWire(method, path, note, "failed: no network", 0, 0);
        throw ApiError(std::nullopt, 0, LinkFailure::eNoNetwork, "no network");
    }
    const std::lock_guard<std::mutex> lock(netMutex_);
    Tunnel& tunnel = tunnelFor(path);
    const auto startedAt = std::chrono::steady_clock::now();
    const auto elapsedMillis = [&startedAt]() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startedAt)
            .count();
    };
    const auto failed = [&](const std::string& why) {
        noteWire(method, path, note, "failed: " + why, 0, elapsedMillis());
    };
    // A request no tunnel carried was never put to the server, whatever stopped the tunnel.
    const auto openTunnel = [&]() {
        bool opened = false;
        try {
            opened = ensureSessionLocked(tunnel);
        } catch (const std::exception& error) {
            failed(error.what());
            throw;
        }
        if (!opened) {
            const std::string reason = tunnel.lastError.empty()
                ? std::string("no tunnel to the server")
                : "no tunnel to the server: " + tunnel.lastError;
            failed(reason);
            throw ApiError(std::nullopt, 0, tunnel.lastFailure, reason);
        }
    };
    openTunnel();
    const auto macHeaders = [&]() {
        const std::uint64_t seq = tunnel.sessionSeq + 1;
        const auth::Headers mac = auth::macRequest(auth::sessionHandle(tunnel.sessionSecret, seq),
            tunnel.sessionKey, seq, nowSeconds(), method, query.empty() ? path : path + "?" + query,
            body.bytes());
        return std::map<std::string, std::string>(mac.begin(), mac.end());
    };
    const bool quietOnSuccess = path == kEventsPath;
    const auto accept = [&](const ApiResponse& response) {
        if (!answeredWell(response.status)) {
            linkFailure_.store(LinkFailure::eServerRefused);
            raiseAnswered(response.status, response.body, LinkFailure::eNone);
        }
        if (!quietOnSuccess) {
            noteWire(method, path, note, std::to_string(response.status), response.body.size(),
                elapsedMillis());
        }
    };
    try {
        const ApiResponse response = tunnelledLocked(
            tunnel, method, path, query, body, contentType, macHeaders(), readTimeoutSeconds);
        accept(response);
        return response;
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eSessionInvalid || tunnel.sessionId.empty()) {
            failed(error.what());
            throw;
        }
        bazarish::log::info("the server no longer holds the tunnel; opening another");
        tunnel.sessionId.clear();
        openTunnel();
        const ApiResponse response = tunnelledLocked(
            tunnel, method, path, query, body, contentType, macHeaders(), readTimeoutSeconds);
        accept(response);
        return response;
    }
}

ApiResponse ApiClient::transmitLocked(const std::string& method, const std::string& path,
    const Bytes& body, const std::string& contentType, const int readTimeoutSeconds)
{
    std::map<std::string, std::string> i2pHeaders;
    if (!body.empty() && !contentType.empty()) {
        i2pHeaders["Content-Type"] = contentType;
    }

    const auto loopbackAttempt = [&](const Facade& facade) -> bazarish::http::ClientResponse {
        bazarish::http::ClientRequest out;
        out.method = method;
        out.target = path;
        out.body = std::string(body.begin(), body.end());
        if (!body.empty()) {
            out.contentType = contentType;
        }
        return bazarish::http::request(
            facade.host, facade.port != 0 ? facade.port : kPlainHttpPort, out,
            facadeOptions(readTimeoutSeconds));
    };

    const std::vector<Facade>& facades = endpoint_.facades;
    const std::vector<std::size_t> attempts = facadeOrder();
    std::string lastError = "no facade configured";
    LinkFailure lastFailure = LinkFailure::eServerUnreachable;
    for (const std::size_t index : attempts) {
        const Facade& facade = facades[index];

        if (facadeIsI2p(facade)) {
            if (i2pDataDir_.empty()) {
                lastError = "i2p facade without an I2P transport: " + shortHost(facade.host);
                continue;
            }
            LinkAttempt attempt;
            attempt.viaGateway = usingGatewayTransport();
            std::optional<ApiResponse> response;
            try {
                response = i2pExchange(facade, method, path, i2pHeaders, body.size(),
                    [&body](WatchedStream& stream) {
                        stream.writeAll(body);
                    },
                    readTimeoutSeconds, attempt);
            } catch (const bazarish::i2p::GatewayRefusal&) {
                attempt.gatewayRefused = true;
                noteLinkFailure(attempt);
                throw;
            } catch (const std::exception&) {
                noteLinkFailure(attempt);
                throw;
            }
            if (!response) {
                lastFailure = noteLinkFailure(attempt);
                lastError = "i2p facade unreachable: " + shortHost(facade.host);
                continue;
            }
            activeFacade_ = index;
            attempt.status = response->status;
            const LinkFailure answered = noteLinkFailure(attempt);
            if (response->status < 200 || response->status >= 300) {
                raiseAnswered(response->status, response->body, answered);
            }
            return *response;
        }

        const bazarish::http::ClientResponse result = loopbackAttempt(facade);
        LinkAttempt attempt;
        attempt.reached = LinkStage::eExchange;
        attempt.status = result.status;
        const LinkFailure answered = noteLinkFailure(attempt);
        if (result.status == 0) {
            lastFailure = answered;
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
        if (response.status < 200 || response.status >= 300) {
            raiseAnswered(response.status, response.body, answered);
        }
        return response;
    }
    throw ApiError(std::nullopt, 0, lastFailure, "no facade answered: " + lastError);
}

}  // namespace bazarish::client
