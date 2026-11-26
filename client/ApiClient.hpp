// Bazarish project (c) 2026
#pragma once

#include "LinkFailure.hpp"
#include "MailWaitGate.hpp"
#include "WatchedStream.hpp"
#include "WireLog.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Devices.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/SecretBytes.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
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

struct Facade {
    std::string host;
    int port = 0;

    bool operator==(const Facade&) const = default;
};

Facade parseFacadeAddress(const std::string& address);
std::string facadeAddress(const Facade& facade);

struct ServerEndpoint {
    std::string serverFingerprint;
    std::vector<Facade> facades;
    std::vector<std::string> reseeds;

    bool operator==(const ServerEndpoint&) const = default;
};

inline constexpr const char* kEventsPath = "/v1/messaging/events";
inline constexpr const char* kEventsHoldQuery = "hold=1";
inline constexpr const char* kEventsDeferredKey = "deferred";
inline constexpr const char* kEventsDevicesKey = "devices";
inline constexpr char kEventsDeferredSeparator = ',';

struct ApiResponse {
    int status = 0;
    Bytes body;

    nlohmann::json json() const;
};

class ApiError : public LinkError {
public:
    ApiError(std::optional<ErrorCode> code, int httpStatus, LinkFailure failure,
        const std::string& message);

    std::optional<ErrorCode> code;
    int httpStatus = 0;
};

class ApiClient {
public:
    static constexpr int kDefaultReadTimeoutSeconds = 240;
    static constexpr int kConnectTimeoutSeconds = 30;
    static constexpr int kWriteTimeoutSeconds = kDefaultReadTimeoutSeconds;

    ApiClient(const DeviceCredential& credential, ServerEndpoint endpoint,
        std::filesystem::path i2pDataDir = {});

    ApiResponse get(const std::string& path, const std::string& query = "");
    ApiResponse getWaiting(const std::string& path, const std::string& query, int readTimeoutSeconds);
    ApiResponse postJson(const std::string& path, const nlohmann::json& body,
        int readTimeoutSeconds = kDefaultReadTimeoutSeconds, const std::string& note = {});
    ApiResponse del(const std::string& path, const nlohmann::json& body = nlohmann::json());
    bool deviceRevoked() const { return deviceRevoked_.load(); }
    void onDeviceRevoked(std::function<void()> tell);
    // Told each stage an I2P attempt reaches, on the calling thread.
    void onLinkStage(std::function<void(LinkStage)> tell);
    // A JSON body the caller wrote into a wiped buffer, carried into the tunnel without a copy.
    ApiResponse postSecret(const std::string& path, const SecretBytes& jsonBody);

    void setWireLog(std::shared_ptr<WireLog> log);

    const ServerEndpoint& endpoint() const;
    std::string activeFacadeAddress() const;
    std::string gatewayRefusal() const;
    // The last facade that answered said the server behind it is unreachable.
    bool serverBehindFacadeDown() const;
    LinkFailure linkFailure() const;
    void setAccountLabel(std::string accountLabel);
    void releaseI2pLink();
    // A closed client never dials again, so a held request it carries ends for good.
    void close();
    // Asks the netDb for the facade's lease set past the link's cache.
    FacadeLookup lookFacadeUp();
    FacadeLink facadeLink() const;
    void liftStandOff();

private:
    void noteWire(const std::string& method, const std::string& path, const std::string& note,
        const std::string& status, std::size_t bytes, std::int64_t elapsedMillis);

    ApiResponse send(const std::string& method, const std::string& path,
        const std::string& query, const SecretBytes& body, const std::string& contentType,
        int readTimeoutSeconds = kDefaultReadTimeoutSeconds, const std::string& note = {});
    ApiResponse transmitLocked(const std::string& method, const std::string& path,
        const Bytes& body, const std::string& contentType, int readTimeoutSeconds);

    [[noreturn]] void raiseAnswered(int status, const Bytes& body, LinkFailure failure);

    static bool facadeIsI2p(const Facade& facade);
    static bool facadeIsOwnLoopback(const Facade& facade);
    std::vector<std::size_t> facadeOrder() const;
    void reach(LinkAttempt& tried, LinkStage stage);
    std::optional<ApiResponse> i2pExchange(const Facade& facade, const std::string& method,
        const std::string& path, const std::map<std::string, std::string>& headers,
        std::size_t bodyLen, const std::function<void(WatchedStream&)>& writeBody,
        int readTimeoutSeconds, LinkAttempt& tried);
    LinkFailure noteLinkFailure(LinkAttempt attempt);

    const DeviceCredential& credential_;
    const ServerEndpoint endpoint_;
    const std::filesystem::path i2pDataDir_;
    std::string accountLabel_;

    struct Tunnel {
        explicit Tunnel(const ServerCard::Service service)
            : service(service)
        {
        }

        const ServerCard::Service service;
        Bytes sealingKeyDer;
        std::string sessionId;
        SecretBytes sessionSecret;
        SecretBytes sessionKey;
        SecretBytes tunnelKey;
        std::int64_t sessionUntil = 0;
        std::uint64_t sessionSeq = 0;
        std::int64_t blockedUntil = 0;
        std::uint64_t blockedAtCarry = 0;
        std::string lastError;
        LinkFailure lastFailure = LinkFailure::eNone;
    };
    Tunnel& tunnelFor(const std::string& path);
    bool ensureSessionLocked(Tunnel& tunnel);
    void standOffAfterSilenceLocked(Tunnel& tunnel);
    void ensureSealingKeyLocked(Tunnel& tunnel);
    ApiResponse tunnelledLocked(Tunnel& tunnel, const std::string& method,
        const std::string& path, const std::string& query, const SecretBytes& body,
        const std::string& contentType, const std::map<std::string, std::string>& headers,
        int readTimeoutSeconds);

    Tunnel messaging_{ServerCard::Service::eMessaging};
    Tunnel serverService_{ServerCard::Service::eServerService};
    std::string gatewayRefusal_;
    std::atomic<LinkFailure> linkFailure_{LinkFailure::eNone};
    std::atomic<bool> deviceRevoked_{false};
    std::mutex revokedMutex_;
    std::function<void()> tellRevoked_;
    std::mutex stageMutex_;
    std::function<void(LinkStage)> tellStage_;
    std::atomic<bool> closed_{false};

    std::shared_ptr<WireLog> wireLog_;
    std::shared_ptr<bazarish::i2p::Endpoint> i2pOut_;
    std::string i2pOutHost_;
    std::unique_ptr<bazarish::i2p::Stream> i2pStream_;
    std::chrono::steady_clock::time_point i2pStreamUsedAt_;
    std::size_t activeFacade_ = 0;
    mutable std::mutex netMutex_;
    // Apart from netMutex_, which a request holds for minutes: a release must not wait for it.
    std::mutex linkMutex_;
    std::weak_ptr<bazarish::i2p::Endpoint> link_;
};

}  // namespace bazarish::client
