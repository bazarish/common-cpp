// Bazarish project (c) 2026
#include "Client.hpp"

#include <bazarish/Errors.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/Resolve.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <ctime>

namespace bazarish::client {

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

}  // namespace

namespace {

Bytes cardQueryBytes(const CardFetchQuery& query)
{
    const std::string text = toJson(query).dump();
    return Bytes(text.begin(), text.end());
}

}  // namespace

Bytes sealDeliveryEnvelope(const std::string& deliveryClass, const std::string& mailbox,
    const std::string& deliveryId, const Bytes& pass, const Key& recipientSealingKey)
{
    nlohmann::json inner = {
        {"class", deliveryClass},
        {"mailbox", mailbox},
        {"deliveryId", deliveryId},
    };
    if (!pass.empty()) {
        inner["pass"] = toBase64(pass);
    }
    const std::string text = inner.dump();
    return cms::seal(Bytes(text.begin(), text.end()), recipientSealingKey);
}

Client::Client(Identity identity, std::string clientId, ServerEndpoint endpoint,
    std::filesystem::path i2pDataDir)
    : identity_(std::move(identity))
    , api_(identity_, std::move(clientId), std::move(endpoint), std::move(i2pDataDir))
{
    api_.setWireLog(log_.get());
}

WireLog& Client::wireLog()
{
    return *log_;
}

std::shared_ptr<WireLog> Client::wireLogHandle() const
{
    return log_;
}

const Identity& Client::identity() const
{
    return identity_;
}

const std::string& Client::clientId() const
{
    return api_.clientId();
}

const ServerEndpoint& Client::endpoint() const
{
    return api_.endpoint();
}

std::string Client::activeFacadeUrl() const
{
    return api_.activeFacadeUrl();
}

void Client::setDestinationOwner(std::string owner)
{
    api_.setDestinationOwner(std::move(owner));
}

void Client::releaseI2pLink()
{
    api_.releaseI2pLink();
}

PublishResult Client::publishCard(const Bytes& sealingPrekeyDer, const std::string& ownDest,
    const std::int64_t notBefore)
{
    const DestinationInfo destination = myDestination();
    const std::string dest = destination.dest.empty() ? ownDest : destination.dest;
    const std::int64_t issuedAt = std::max(nowSeconds(), notBefore + 1);
    const Bytes card = ContactCard::issue(
        identity_, issuedAt, dest, sealingPrekeyDer, destination.servingSealingKeyDer);
    const ApiResponse response = api_.postJson("/v1/account/card", {{"card", toBase64(card)}});
    const nlohmann::json body = response.json();

    PublishResult result;
    result.cardDer = card;
    result.quotaBytes = body.at("quotaBytes").get<std::uint64_t>();
    result.view = body.value("view", std::string());
    result.dest = dest;
    result.servingSealingKeyDer = destination.servingSealingKeyDer;
    return result;
}

Client::PreparedServingKey Client::prepareServingKey()
{
    const ApiResponse response = api_.postJson("/v1/account/serving-key", nlohmann::json::object());
    const nlohmann::json body = response.json();
    PreparedServingKey prepared;
    prepared.servingSealingKeyDer = fromBase64(body.at("servingKey").get<std::string>());
    prepared.view = body.at("view").get<std::string>();
    return prepared;
}

void Client::commitServingKey(const Bytes& cardDer)
{
    (void)api_.postJson("/v1/account/serving-key/commit", {{"card", toBase64(cardDer)}}).json();
}

void Client::closeAccount()
{
    api_.del("/v1/account/registration");
}

PortalInfo Client::fetchPortalInfo()
{
    const ApiResponse response = api_.get("/v1/account/portal");
    const nlohmann::json body = response.json();
    PortalInfo info;
    info.message = body.value("message", std::string());
    if (const auto links = body.find("links"); links != body.end() && links->is_array()) {
        for (const nlohmann::json& link : *links) {
            if (link.is_string()) {
                info.links.push_back(link.get<std::string>());
            }
        }
    }
    return info;
}

void Client::registerHere()
{
    (void)api_.postJson("/v1/account/registration", nlohmann::json::object()).json();
}

void Client::sendI2pTransient(const std::string& transientB64, const std::int64_t expiresUnix)
{
    api_.postJson(
        "/v1/account/i2p-dest", {{"transient", transientB64}, {"expiresUnix", expiresUnix}});
}

I2pDestStatus Client::i2pStatus()
{
    const ApiResponse response = api_.get("/v1/account/i2p-status");
    const nlohmann::json body = response.json();
    I2pDestStatus status;
    status.approval = body.value("approval", std::string());
    status.registrationMessage = body.value("registrationMessage", std::string());
    status.transientExpires = body.value("transientExpires", std::int64_t{0});
    status.transientUpdatedAt = body.value("transientUpdatedAt", std::int64_t{0});
    return status;
}

StorageUsage Client::storageUsage()
{
    StorageUsage usage;
    try {
        const nlohmann::json body = api_.get("/v1/messaging/storage-usage").json();
        usage.mailboxUsedBytes = body.value("usedBytes", std::uint64_t{0});
        usage.mailboxQuotaBytes = body.value("quotaBytes", std::uint64_t{0});
        usage.mailboxOk = true;
    } catch (const std::exception& error) {
        bazarish::log::warn("storage usage unavailable: {}", error.what());
    }
    return usage;
}

ContactInfo Client::fetchCard(const Descriptor& descriptor, const FetchTransport& transport)
{
    const FetchOutcome outcome = transport(descriptor.dest, "card",
        cardQueryBytes(CardFetchQuery{descriptor.fingerprint, descriptor.view}));
    if (!outcome.ok) {
        throw std::runtime_error("that invite is out of date - ask for a new one");
    }

    ContactInfo info;
    info.card = ContactCard::verify(outcome.sealed);
    if (info.card.fingerprint() != descriptor.fingerprint) {
        throw std::runtime_error("fetched card is for a different fingerprint");
    }
    validateB32I2pHost(info.card.dest);
    return info;
}

Descriptor Client::resolveAlias(const std::string& alias, const ResolverCoordinate& resolver,
    const std::int64_t now, const FetchTransport& transport)
{
    const std::string queryJson = toJson(ResolveQuery{alias}).dump();
    const FetchOutcome outcome
        = transport(resolver.dest, "resolve", Bytes(queryJson.begin(), queryJson.end()));
    if (!outcome.ok) {
        const std::string code
            = outcome.errorCode.empty() ? std::string(toString(ErrorCode::eAliasUnknown))
                                        : outcome.errorCode;
        log::info("alias {} did not resolve: {}", alias, code);
        const std::optional<ErrorCode> known = errorCodeFromString(code);
        throw std::runtime_error(known ? std::string(readable(*known))
                                       : "The alias registry refused to answer.");
    }
    const ResolveResponse fetched
        = resolveResponseFromJson(nlohmann::json::parse(outcome.sealed));

    const ResolveRecord record = verifyResolveRecord(fetched.recordDer, fetched.delegationDer,
        fetched.aliasCertDer, resolver.rootFingerprint, now);
    if (record.alias != alias) {
        throw std::runtime_error("resolver returned a record for a different alias");
    }
    return record.descriptor;
}

DestinationInfo Client::myDestination()
{
    const ApiResponse response = api_.get("/v1/messaging/destination");
    const nlohmann::json body = response.json();
    DestinationInfo info;
    info.dest = body.at("dest").get<std::string>();
    info.state = body.value("state", std::string());
    if (!info.dest.empty()) {
        validateB32I2pHost(info.dest);
    }
    const std::string servingKey = body.value("servingKey", std::string());
    if (!servingKey.empty()) {
        info.servingSealingKeyDer = fromBase64(servingKey);
    }
    return info;
}

void Client::registerThisClient()
{
    api_.postJson("/v1/messaging/clients", {{"clientId", api_.clientId()}});
}

std::vector<Client::DeviceEntry> Client::listClients()
{
    const ApiResponse response = api_.get("/v1/messaging/clients");
    const nlohmann::json body = nlohmann::json::parse(response.body.begin(), response.body.end());
    std::vector<DeviceEntry> devices;
    for (const nlohmann::json& entry : body.at("clients")) {
        devices.push_back(DeviceEntry{entry.at("clientId").get<std::string>(),
            entry.value("current", false),
            entry.value("queue", static_cast<std::size_t>(0))});
    }
    return devices;
}

void Client::retireClient(const std::string& clientId)
{
    api_.del("/v1/messaging/clients/" + clientId);
}

void Client::registerPasses(const std::vector<Bytes>& handles)
{
    nlohmann::json encoded = nlohmann::json::array();
    for (const Bytes& handle : handles) {
        encoded.push_back(toBase64(handle));
    }
    api_.postJson("/v1/messaging/passes", {{"passes", encoded}});
}

std::size_t Client::revokePasses(const std::vector<Bytes>& handles)
{
    nlohmann::json encoded = nlohmann::json::array();
    for (const Bytes& handle : handles) {
        encoded.push_back(toBase64(handle));
    }
    return api_.postJson("/v1/messaging/passes/revoke", {{"passes", encoded}})
        .json()
        .at("revoked")
        .get<std::size_t>();
}

std::vector<PendingEntry> Client::waitForPending(const int waitSeconds)
{
    constexpr int kReadSlackSeconds = 20;
    const ApiResponse response = api_.getWaiting(
        kEventsPath, "wait=" + std::to_string(waitSeconds), waitSeconds + kReadSlackSeconds);
    const nlohmann::json body = response.json();
    std::vector<PendingEntry> entries;
    for (const nlohmann::json& entry : body.at("pending")) {
        entries.push_back(
            {entry.at("id").get<std::string>(), entry.at("class").get<std::string>()});
    }
    if (!entries.empty()) {
        log_->record({0, false, "poll: " + std::to_string(entries.size()) + " waiting", "200", {}});
    }
    return entries;
}

std::vector<PendingEntry> Client::listPending()
{
    const ApiResponse response = api_.get("/v1/messaging/pending");
    const nlohmann::json body = response.json();

    std::vector<PendingEntry> entries;
    for (const nlohmann::json& entry : body.at("pending")) {
        entries.push_back(
            {entry.at("id").get<std::string>(), entry.at("class").get<std::string>()});
    }
    return entries;
}

std::string deliveryIdFor(
    const std::string& secretKey, const std::string& e2eId, const std::string& mailbox)
{
    constexpr std::size_t kDeliveryIdHexChars = 32;
    return bazarish::service::hmacSha256Hex(secretKey, e2eId + "|" + mailbox)
        .substr(0, kDeliveryIdHexChars);
}

Bytes Client::fetchBlob(const std::string& blobId)
{
    const ApiResponse response = api_.get("/v1/messaging/pending/" + blobId);
    return response.body;
}

void Client::ack(const std::string& blobId)
{
    api_.postJson("/v1/messaging/ack", {{"blobId", blobId}});
}

void Client::submitSelf(
    const std::string& deliveryId, const Bytes& payload, const std::string& kind)
{
    api_.postJson("/v1/messaging/self",
        {{"deliveryId", deliveryId}, {"payload", toBase64(payload)}},
        ApiClient::kDefaultReadTimeoutSeconds, kind);
}

}  // namespace bazarish::client
