// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/I2p.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace bazarish::client {

// Reports upload progress as (bytes sent so far, total bytes). Invoked from the
// thread driving the upload; called repeatedly as the body streams out.
using UploadProgressFn = std::function<void(std::uint64_t sent, std::uint64_t total)>;

// One facade entry point, parsed from a single URL. A server may expose several
// facades; the client tries them in order and fails over (see ServerEndpoint).
struct Facade {
    bool tls = false;          // https vs http
    std::string host;
    int port = 0;              // defaults to 443 (https) / 80 (http) when omitted
    // Secret URI prefix the facade strips, e.g. "/s/9f3c". Empty when the
    // reverse proxy owns the secret.
    std::string basePath;
};

// Parses "http[s]://host[:port][/base/path]" into a Facade. Throws on a malformed
// URL. A bare "host:port" with no scheme is treated as http.
Facade parseFacadeUrl(const std::string& url);
// Formats a Facade back into its canonical URL string.
std::string facadeToUrl(const Facade& facade);

// Where the client reaches the infrastructure: the serving server's fingerprint
// (the trust anchor) and an ordered list of facades the transport tries and
// fails over across. A facade's secret base path is prepended to every request
// URL but excluded from the signed canonical path (the facade strips it before
// forwarding, and the server verifies the stripped path).
struct ServerEndpoint {
    // Fingerprint of the server root key (from the registration info). Used to
    // name subscription certificates and as the local mailbox server.
    std::string serverFingerprint;
    // The ordered facades; empty means "not connected to a server yet". Every one
    // of them is an I2P address: this client talks to its server over I2P and
    // nothing else.
    std::vector<Facade> facades;
    // Clearnet addresses used for exactly one request - the slice of netdb a
    // router with no peers starts from. No API is spoken here, and once the
    // router is up they are not asked again.
    std::vector<Facade> reseeds;
};


// A server response. Non-2xx statuses are turned into ApiError by ApiClient,
// so callers only ever see successful responses here.
struct ApiResponse {
    int status = 0;
    Bytes body;
    std::string contentType;
    // Response header names lowercased (e.g. the blob proxy's "x-blob-total").
    std::map<std::string, std::string> headers;

    nlohmann::json json() const;
};

// Raised for every non-success outcome: typed server error envelopes and
// transport-level failures alike. code is set only when the body carried a
// recognized error envelope; transport failures and unrecognized bodies
// leave it empty.
class ApiError : public std::runtime_error {
public:
    ApiError(std::optional<ErrorCode> code, int httpStatus, const std::string& message);

    std::optional<ErrorCode> code;
    // 0 when there was no HTTP response at all (transport failure).
    int httpStatus = 0;
};

// Low-level signed HTTP transport for the client API. Holds a reference to
// the caller's identity (which must outlive the transport) and signs every
// authenticated request with both identity keys.
class ApiClient {
public:
    // Read timeout (seconds) for a normal request. Generous because a mailbox
    // fetch travels to this account's server over I2P (tens of seconds).
    static constexpr int kDefaultReadTimeoutSeconds = 240;
    // Connecting is local (the facade is one TCP hop away), so a connect that
    // takes this long is a dead facade, not a slow one. Writing gets the same
    // budget as reading: an upload streams for as long as a response may take.
    static constexpr int kConnectTimeoutSeconds = 30;
    static constexpr int kWriteTimeoutSeconds = kDefaultReadTimeoutSeconds;

    // i2pDataDir is the embedded router's data directory; it enables routing
    // facades whose host ends in ".b32.i2p" over I2P. When empty, only clearnet
    // facades are usable (i2p facades are treated as unreachable) - the CLI and
    // tests that never touch I2P leave it unset.
    ApiClient(const Identity& identity, std::string clientId, ServerEndpoint endpoint,
        std::filesystem::path i2pDataDir = {});

    // Authenticated requests. path is the server-visible path (no base path,
    // no query string); query, when non-empty, is appended to the URL only.
    // Every non-2xx response throws ApiError.
    ApiResponse get(const std::string& path, const std::string& query = "");
    // A GET the server is expected to hold open (the event face). The read
    // timeout has to outlast the wait the server was asked for, or the client
    // would tear down its own long poll.
    ApiResponse getWaiting(const std::string& path, const std::string& query, int readTimeoutSeconds);
    // readTimeoutSeconds bounds how long to wait for the response.
    ApiResponse postJson(const std::string& path, const nlohmann::json& body,
        int readTimeoutSeconds = kDefaultReadTimeoutSeconds);
    ApiResponse postBytes(
        const std::string& path, const Bytes& body, const std::string& contentType);
    // Authenticated PUT with extra request headers (e.g. blob retention).
    ApiResponse putBytes(const std::string& path, const Bytes& body,
        const std::string& contentType,
        const std::map<std::string, std::string>& extraHeaders = {});
    // Authenticated PUT that streams a file as the body without reading it into
    // memory: the request is signed over the precomputed body digest
    // (bodySha256Hex) and the file is fed to the connection through a content
    // provider. Used for large blob upload.
    ApiResponse putFile(const std::string& path, const std::filesystem::path& filePath,
        const std::string& bodySha256Hex, const std::string& contentType,
        const std::map<std::string, std::string>& extraHeaders = {},
        const UploadProgressFn& onProgress = {});
    ApiResponse del(const std::string& path, const nlohmann::json& body = nlohmann::json());

    // Unauthenticated GET (alias resolution is findable by design).
    ApiResponse getPublic(const std::string& path, const std::string& query = "");
    // Unauthenticated GET pinned to a CLEARNET facade. Its one caller is the
    // private reseed, which bootstraps the very transport an I2P facade needs:
    // routing it over I2P would ask the router to start before it has a netDb,
    // and would deadlock outright - the reseed runs while the router lock is held.
    ApiResponse getClearnet(const std::string& path, const std::string& query = "");

    const std::string& clientId() const;
    const ServerEndpoint& endpoint() const;
    // The facade the transport is currently using (last one that worked), as a
    // URL - for the GUI's "connected via" display.
    std::string activeFacadeUrl() const;
    // Names this account on the destinations this client creates, so a router
    // shared by several accounts says whose dialer is whose.
    void setDestinationOwner(std::string owner);
    // Drops this client's I2P destination, tearing down its tunnels. The next
    // request over an I2P facade builds a fresh one. Used when an account goes
    // offline: an account that is not talking should not be holding tunnels open.
    void releaseI2pLink();

    // The session this client authenticates with, when it has one. Opening it
    // costs one signed request; every request after that carries a MAC instead of
    // an ~8.3 KB hybrid signature. The caller supplies the sealing key the secret
    // is sealed to (this user's serving key, whose private half the server holds)
    // and the key to unseal nothing with - the server only answers with an id.
    void setSessionSealingKey(Bytes servingSealingKeyDer);
    // What this client's outbound destination is called in the router status
    // view. An account keeps two: the one its session dials with, and the one that
    // holds the long poll open (they are separate so a wait never blocks a send).

private:
    // Seeds the embedded router's netDb from our own server before it is ever
    // started, so a first start never falls back to a public reseed host. Every
    // path that starts the router goes through here, because an I2P facade
    // request would otherwise start it with an empty netDb.
    void seedRouterFromServer();

    ApiResponse send(const std::string& method, const std::string& path,
        const std::string& query, const Bytes& body, const std::string& contentType,
        bool authenticate, const std::map<std::string, std::string>& extraHeaders = {},
        int readTimeoutSeconds = kDefaultReadTimeoutSeconds, bool clearnetOnly = false);
    // The transport half of send: everything from the request lock onward, with
    // the headers already decided. Opening a session reuses it while the lock is
    // held, which is why it is separate.
    ApiResponse transmitLocked(const std::string& method, const std::string& path,
        const std::string& query, const Bytes& body, const std::string& contentType,
        const std::map<std::string, std::string>& headers, int readTimeoutSeconds,
        bool clearnetOnly);


    // True if a facade's host ends in ".b32.i2p" (reached over the embedded I2P
    // transport rather than clearnet).
    static bool facadeIsI2p(const Facade& facade);
    // The order facades are tried in: I2P facades first (preferred), then
    // clearnet, preserving each group's configured order.
    std::vector<std::size_t> facadeOrder() const;
    // Performs one HTTP/1.1 exchange to an I2P facade over the persistent
    // outbound destination. writeBody streams the request body onto the stream
    // after the head (bodyLen must equal the bytes it writes). Returns nullopt
    // when the facade is unreachable. Throws only on a malformed response.
    std::optional<ApiResponse> i2pExchange(const Facade& facade, const std::string& method,
        const std::string& fullPath, const std::map<std::string, std::string>& headers,
        std::size_t bodyLen, const std::function<void(bazarish::i2p::Stream&)>& writeBody);

    const Identity& identity_;
    const std::string clientId_;
    const ServerEndpoint endpoint_;
    // The embedded router's data dir (empty -> no I2P transport; i2p facades are
    // then unreachable).
    const std::filesystem::path i2pDataDir_;
    // Account name carried onto this client's destinations (status view only).
    std::string destinationOwner_;

    // Session authentication. sessionUntil_ is what the server told us, so a
    // client renews before it lapses rather than after a refusal. sessionBlocked_
    // is the loop guard: a server that refuses a freshly issued session is not
    // arguing about this session, so we stop asking for a while and keep signing.
    Bytes sessionSealingKeyDer_;
    std::string sessionId_;
    Bytes sessionSecret_;
    Bytes sessionKey_;
    std::int64_t sessionUntil_ = 0;
    std::uint64_t sessionSeq_ = 0;
    std::int64_t sessionBlockedUntil_ = 0;
    // Consecutive sessions refused on their first use. A server that issues
    // sessions and then rejects them is not going to be argued out of it, so the
    // client stops opening them for a while instead of one per request.
    int sessionRefusals_ = 0;
    // Opens a session if one is due and possible. Returns whether a usable one is
    // in hand. Called with netMutex_ held.
    bool ensureSessionLocked();
    // A persistent unpublished outbound destination that dials I2P facades; its
    // tunnels stay warm across requests (a fresh transient per call would rebuild
    // a destination on every poll). Created lazily on first I2P facade use.
    std::shared_ptr<bazarish::i2p::Endpoint> i2pOut_;
    // The connection to the facade, kept between requests. Every request of this
    // client is serialized on netMutex_, so one is enough; a stale one is dropped
    // and redialled on its next use.
    std::unique_ptr<bazarish::i2p::Stream> i2pStream_;
    // Index of the last facade that worked; the GUI "connected via" reads it.
    std::size_t activeFacade_ = 0;
    // Serializes the two network entry points (send / putFile) so the client is
    // safe to call from more than one thread: a blob download running off the main
    // worker thread may take the own-server proxy fallback, which goes through this
    // client concurrently with the worker's sync/sends. Guards the shared lazily
    // created outbound endpoint and the active-facade index.
    mutable std::mutex netMutex_;
};

}  // namespace bazarish::client
