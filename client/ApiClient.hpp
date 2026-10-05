// Bazarish project (c) 2026
#pragma once

#include "WireLog.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/I2p.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
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

using UploadProgressFn = std::function<void(std::uint64_t sent, std::uint64_t total)>;

struct Facade {
    bool tls = false;
    std::string host;
    int port = 0;
    // Secret URI prefix the facade strips, e.g.
    std::string basePath;
};

Facade parseFacadeUrl(const std::string& url);
std::string facadeToUrl(const Facade& facade);

struct ServerEndpoint {
    std::string serverFingerprint;
    std::vector<Facade> facades;
    std::vector<std::string> reseeds;
};

inline constexpr const char* kEventsPath = "/v1/messaging/events";

struct ApiResponse {
    int status = 0;
    Bytes body;
    std::string contentType;
    std::map<std::string, std::string> headers;

    nlohmann::json json() const;
};

class ApiError : public std::runtime_error {
public:
    ApiError(std::optional<ErrorCode> code, int httpStatus, const std::string& message);

    std::optional<ErrorCode> code;
    int httpStatus = 0;
};

class ApiClient {
public:
    static constexpr int kDefaultReadTimeoutSeconds = 240;
    static constexpr int kConnectTimeoutSeconds = 30;
    static constexpr int kWriteTimeoutSeconds = kDefaultReadTimeoutSeconds;

    ApiClient(const Identity& identity, std::string clientId, ServerEndpoint endpoint,
        std::filesystem::path i2pDataDir = {});

    ApiResponse get(const std::string& path, const std::string& query = "");
    ApiResponse getWaiting(const std::string& path, const std::string& query, int readTimeoutSeconds);
    ApiResponse postJson(const std::string& path, const nlohmann::json& body,
        int readTimeoutSeconds = kDefaultReadTimeoutSeconds, const std::string& note = {});
    ApiResponse del(const std::string& path, const nlohmann::json& body = nlohmann::json());

    void setWireLog(WireLog* log);

    const std::string& clientId() const;
    const ServerEndpoint& endpoint() const;
    std::string activeFacadeUrl() const;
    void setDestinationOwner(std::string owner);
    void releaseI2pLink();

    static std::int64_t sessionBackoffSeconds(int httpStatus);

private:
    void noteWire(const std::string& method, const std::string& path, const std::string& note,
        const std::string& status, std::size_t bytes, std::int64_t elapsedMillis);

    ApiResponse send(const std::string& method, const std::string& path,
        const std::string& query, const Bytes& body, const std::string& contentType,
        bool authenticate, const std::map<std::string, std::string>& extraHeaders = {},
        int readTimeoutSeconds = kDefaultReadTimeoutSeconds,
        const std::string& note = {});
    ApiResponse transmitLocked(const std::string& method, const std::string& path,
        const std::string& query, const Bytes& body, const std::string& contentType,
        const std::map<std::string, std::string>& headers, int readTimeoutSeconds);

    static bool facadeIsI2p(const Facade& facade);
    static bool facadeIsOwnLoopback(const Facade& facade);
    std::vector<std::size_t> facadeOrder() const;
    std::optional<ApiResponse> i2pExchange(const Facade& facade, const std::string& method,
        const std::string& fullPath, const std::map<std::string, std::string>& headers,
        std::size_t bodyLen, const std::function<void(bazarish::i2p::Stream&)>& writeBody,
        int readTimeoutSeconds);

    const Identity& identity_;
    const std::string clientId_;
    const ServerEndpoint endpoint_;
    const std::filesystem::path i2pDataDir_;
    std::string destinationOwner_;

    Bytes serverSealingKeyDer_;
    std::string sessionId_;
    Bytes sessionSecret_;
    Bytes sessionKey_;
    Bytes tunnelKey_;
    std::int64_t sessionUntil_ = 0;
    std::uint64_t sessionSeq_ = 0;
    std::int64_t sessionBlockedUntil_ = 0;
    int sessionRefusals_ = 0;
    std::string lastTunnelError_;
    bool ensureSessionLocked();
    void ensureServerKeyLocked();
    ApiResponse tunnelledLocked(const std::string& method, const std::string& path,
        const std::string& query, const Bytes& body, const std::string& contentType,
        const std::map<std::string, std::string>& headers, int readTimeoutSeconds);

    WireLog* wireLog_ = nullptr;
    std::shared_ptr<bazarish::i2p::Endpoint> i2pOut_;
    std::unique_ptr<bazarish::i2p::Stream> i2pStream_;
    std::chrono::steady_clock::time_point i2pStreamUsedAt_;
    std::size_t activeFacade_ = 0;
    mutable std::mutex netMutex_;
};

}  // namespace bazarish::client
