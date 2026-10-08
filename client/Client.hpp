// Bazarish project (c) 2026
#pragma once

#include "ApiClient.hpp"
#include "ResolverConfig.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Descriptor.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::client {

struct DestinationInfo {
    std::string dest;
    Bytes servingSealingKeyDer;
    std::string state;
};

struct I2pDestStatus {
    std::string approval;
    std::string registrationMessage;
    std::int64_t transientExpires = 0;
    std::int64_t transientUpdatedAt = 0;

    bool approved() const { return approval == "approved"; }
};

struct StorageUsage {
    bool mailboxOk = false;
    std::uint64_t mailboxUsedBytes = 0;
    std::uint64_t mailboxQuotaBytes = 0;
};

struct PublishResult {
    std::uint64_t quotaBytes = 0;
    std::string dest;
    Bytes servingSealingKeyDer;
    Bytes cardDer;
};

struct ContactInfo {
    ContactCard card;
};

struct PendingEntry {
    std::string id;
    std::string deliveryClass;
};

struct PortalInfo {
    std::string message;
    std::vector<std::string> links;
};

struct FetchOutcome {
    bool ok = false;
    Bytes sealed;
    std::string errorCode;
};

using FetchTransport
    = std::function<FetchOutcome(const std::string& toDest, const std::string& op, const Bytes& sealed)>;

Bytes sealDeliveryEnvelope(const std::string& deliveryClass, const std::string& mailbox,
    const std::string& deliveryId, const Bytes& pass, const Key& recipientSealingKey);

std::string deliveryIdFor(
    const std::string& secretKey, const std::string& e2eId, const std::string& mailbox);

class Client {
public:
    Client(Identity identity, std::string clientId, ServerEndpoint endpoint,
        std::filesystem::path i2pDataDir = {});

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    const Identity& identity() const;
    const std::string& clientId() const;
    const ServerEndpoint& endpoint() const;
    std::string activeFacadeUrl() const;

    void setDestinationOwner(std::string owner);
    void releaseI2pLink();

    PublishResult publishCard(const Bytes& sealingPrekeyDer = {}, const std::string& ownDest = {},
        std::int64_t notBefore = 0);

    void closeAccount();
    PortalInfo fetchPortalInfo();
    void registerHere();
    DestinationInfo sendI2pTransient(const std::string& transientB64, std::int64_t expiresUnix);
    I2pDestStatus i2pStatus();
    StorageUsage storageUsage();
    ContactInfo fetchCard(const Descriptor& descriptor, const FetchTransport& transport);
    static Descriptor resolveAlias(const std::string& alias, const ResolverCoordinate& resolver,
        std::int64_t now, const FetchTransport& transport);
    DestinationInfo myDestination();

    void registerThisClient();
    struct DeviceEntry {
        std::string clientId;
        bool current = false;
        std::size_t queued = 0;
    };
    std::vector<DeviceEntry> listClients();
    void retireClient(const std::string& clientId);
    void registerPasses(const std::vector<Bytes>& handles);
    std::size_t revokePasses(const std::vector<Bytes>& handles);
    std::vector<PendingEntry> listPending();
    std::vector<PendingEntry> waitForPending(int waitSeconds);
    Bytes fetchBlob(const std::string& blobId);
    void ack(const std::string& blobId);
    void submitSelf(const std::string& deliveryId, const Bytes& payload,
        const std::string& kind = {});

    WireLog& wireLog();
    std::shared_ptr<WireLog> wireLogHandle() const;

private:
    const Identity identity_;
    std::shared_ptr<WireLog> log_ = std::make_shared<WireLog>();
    ApiClient api_;
};

}  // namespace bazarish::client
