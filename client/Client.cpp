// Bazarish project (c) 2026
#include "Client.hpp"

#include <bazarish/Errors.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/ResolvePuzzle.hpp>
#include <bazarish/Resolve.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <ctime>
#include <thread>

namespace bazarish::client {

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

}  // namespace

namespace {

constexpr unsigned kMaxPuzzleThreads = 4;

unsigned puzzleThreads()
{
    return std::clamp(std::thread::hardware_concurrency(), 1u, kMaxPuzzleThreads);
}

std::vector<PendingEntry> pendingEntries(const nlohmann::json& listed)
{
    std::vector<PendingEntry> entries;
    for (const nlohmann::json& entry : listed) {
        entries.push_back({entry.at("id").get<std::string>(),
            entry.at("class").get<std::string>(), entry.at("bytes").get<std::uint64_t>()});
    }
    return entries;
}

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
    return hybrid::seal(Bytes(text.begin(), text.end()), recipientSealingKey);
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

std::string Client::activeFacadeAddress() const
{
    return api_.activeFacadeAddress();
}

std::string Client::gatewayRefusal() const
{
    return api_.gatewayRefusal();
}

void Client::setDestinationOwner(std::string owner)
{
    api_.setDestinationOwner(std::move(owner));
}

void Client::releaseI2pLink()
{
    api_.releaseI2pLink();
}

PublishResult Client::publishCard(const ContactCard& content, const DestinationInfo& serving,
    const std::int64_t notBefore)
{
    ContactCard signedCard = content;
    signedCard.issuedAt = std::max(nowSeconds(), notBefore + 1);
    signedCard.dest = serving.dest;
    signedCard.servingSealingKeyDer = serving.servingSealingKeyDer;
    const Bytes card = signedCard.issue(identity_);
    const ApiResponse response = api_.postJson("/v1/account/card", {{"card", toBase64(card)}});
    const nlohmann::json body = response.json();

    PublishResult result;
    result.cardDer = card;
    result.quotaBytes = body.at("quotaBytes").get<std::uint64_t>();
    result.dest = serving.dest;
    result.servingSealingKeyDer = serving.servingSealingKeyDer;
    return result;
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

DestinationInfo Client::sendI2pTransient(
    const std::string& transientB64, const std::int64_t expiresUnix, const AddressKeys& keys)
{
    nlohmann::json request = {{"transient", transientB64}, {"expiresUnix", expiresUnix}};
    if (!transientB64.empty()) {
        request["sealingKey"] = keys.sealingPem;
        request["signingKey"] = keys.signingPem;
    }
    const nlohmann::json body = api_.postJson("/v1/account/i2p-dest", request).json();
    DestinationInfo info;
    info.dest = body.value("dest", std::string());
    return info;
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
        cardQueryBytes(CardFetchQuery{descriptor.fingerprint}));
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

Descriptor Client::resolveAlias(const AliasQuery& alias, const ResolverCoordinate& resolver,
    const std::int64_t now, const FetchTransport& transport, const std::function<void()>& solving)
{
    ResolveQuery query{alias.name, alias.word, {}, 0};
    const auto ask = [&resolver, &transport](const ResolveQuery& asked) {
        const std::string queryJson = toJson(asked).dump();
        return transport(resolver.dest, "resolve", Bytes(queryJson.begin(), queryJson.end()));
    };
    FetchOutcome outcome = ask(query);
    if (!outcome.ok && outcome.errorCode == kProofRequiredCode) {
        const nlohmann::json challenge = nlohmann::json::parse(outcome.refusal);
        const std::uint32_t bits = challenge.at("bits").get<std::uint32_t>();
        query.stamp = challenge.at("stamp").get<std::string>();
        log::info(
            "the alias registry asks for {} bits of work before naming {}", bits, alias.name);
        if (solving) {
            solving();
        }
        query.nonce = solvePuzzle(fromHex(query.stamp), bits, puzzleThreads());
        outcome = ask(query);
    }
    if (!outcome.ok) {
        const std::string code
            = outcome.errorCode.empty() ? std::string(toString(ErrorCode::eAliasUnknown))
                                        : outcome.errorCode;
        log::info("alias {} did not resolve: {}", alias.name, code);
        const std::optional<ErrorCode> known = errorCodeFromString(code);
        if (known == ErrorCode::eAliasUnknown) {
            throw AliasUnknown(std::string(readable(*known)));
        }
        throw std::runtime_error(known ? std::string(readable(*known))
                                       : "The alias registry refused to answer.");
    }
    const ResolveResponse fetched
        = resolveResponseFromJson(nlohmann::json::parse(outcome.sealed));

    const ResolveRecord record = verifyResolveRecord(fetched.recordDer, fetched.delegationDer,
        fetched.aliasCertDer, resolver.rootFingerprint, now);
    if (record.alias != alias.name) {
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
    const std::vector<PendingEntry> entries = pendingEntries(response.json().at("pending"));
    if (!entries.empty()) {
        log_->record({0, false, "poll: " + std::to_string(entries.size()) + " waiting", "200", {}});
    }
    return entries;
}

std::vector<PendingEntry> Client::listPending()
{
    return pendingEntries(api_.get("/v1/messaging/pending").json().at("pending"));
}

std::size_t fetchBatchEnd(const std::vector<PendingEntry>& entries, const std::size_t begin)
{
    std::size_t end = begin;
    std::uint64_t carried = 0;
    while (end < entries.size()) {
        carried += entries[end].bytes;
        if (end > begin && carried > kMaxFetchBytes) {
            break;
        }
        ++end;
    }
    return end;
}

std::string deliveryIdFor(
    const std::string& secretKey, const std::string& e2eId, const std::string& mailbox)
{
    constexpr std::size_t kDeliveryIdHexChars = 32;
    return bazarish::service::hmacSha256Hex(secretKey, e2eId + "|" + mailbox)
        .substr(0, kDeliveryIdHexChars);
}

std::vector<FetchedItem> Client::fetch(const std::vector<std::string>& ids)
{
    const nlohmann::json answer
        = nlohmann::json::from_cbor(api_.postJson("/v1/messaging/fetch", {{"ids", ids}}).body);
    std::vector<FetchedItem> items;
    for (const nlohmann::json& item : answer.at("items")) {
        const nlohmann::json::binary_t& blob = item.at("blob").get_binary();
        items.push_back({item.at("id").get<std::string>(), Bytes(blob.begin(), blob.end())});
    }
    return items;
}

void Client::ack(const std::vector<std::string>& ids)
{
    for (std::size_t from = 0; from < ids.size(); from += kMaxAckIdsPerRequest) {
        const std::size_t to = std::min(ids.size(), from + kMaxAckIdsPerRequest);
        api_.postJson("/v1/messaging/ack",
            {{"ids", std::vector<std::string>(ids.begin() + static_cast<std::ptrdiff_t>(from),
                         ids.begin() + static_cast<std::ptrdiff_t>(to))}});
    }
}

void Client::submitSelf(
    const std::string& deliveryId, const Bytes& payload, const std::string& kind)
{
    api_.postJson("/v1/messaging/self",
        {{"deliveryId", deliveryId}, {"payload", toBase64(payload)}},
        ApiClient::kDefaultReadTimeoutSeconds, kind);
}

}  // namespace bazarish::client
