// Bazarish project (c) 2026
#include "Client.hpp"

#include <bazarish/Log.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/Resolve.hpp>

#include <nlohmann/json.hpp>

namespace bazarish::client {

namespace {

// The card query as it goes on the wire: plain CBOR, because the stream it
// travels on is already encrypted to the destination.
Bytes cardQueryBytes(const CardFetchQuery& query)
{
    const std::string text = toJson(query).dump();
    return Bytes(text.begin(), text.end());
}

}  // namespace

Bytes sealDeliveryEnvelope(const std::string& deliveryClass, const std::string& mailbox,
    const std::string& deliveryId, const std::vector<Bytes>& tokens,
    const Key& recipientSealingKey)
{
    nlohmann::json inner = {
        {"class", deliveryClass},
        {"mailbox", mailbox},
        {"deliveryId", deliveryId},
    };
    if (!tokens.empty()) {
        nlohmann::json list = nlohmann::json::array();
        for (const Bytes& token : tokens) {
            list.push_back(toBase64(token));
        }
        inner["tokens"] = std::move(list);
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


PublishResult Client::publishCard(const Bytes& sealingPrekeyDer, const std::string& ownDest)
{
    // Ask the messaging server which destination + serving sealing key it has
    // assigned us, then sign both into the card alongside the sealing prekey.
    // While the destination is still building the server reports no address yet,
    // so the card carries ours: the destination is ours, and its address is the
    // master b32 we already hold.
    const DestinationInfo destination = myDestination();
    const std::string dest = destination.dest.empty() ? ownDest : destination.dest;
    const Bytes card
        = ContactCard::issue(identity_, dest, sealingPrekeyDer, destination.servingSealingKeyDer);
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
    // The answer is the ack: anything else throws, and the caller keeps what it
    // had rather than acting on a rotation that did not happen.
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
    if (const auto registration = body.find("registration");
        registration != body.end() && registration->is_object()) {
        info.captcha = registration->value("captcha", true);
    }
    return info;
}

void Client::registerHere()
{
    // The answer is the ack: a refusal (a server that registers on its portal,
    // or a banned key) throws, and the caller keeps sending the user to the page.
    (void)api_.postJson("/v1/account/registration", nlohmann::json::object()).json();
}

void Client::sendI2pTransient(const std::string& transientB64, const std::int64_t expiresUnix)
{
    // Raises on refusal (a moderated server withholds the destination until an
    // operator approves the account), which the caller must not hide: without a
    // delegation the user has no routing at all.
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
    // Best effort: a server that does not answer leaves the figures stale rather
    // than failing the settings page they are shown on.
    try {
        const nlohmann::json body = api_.get("/v1/messaging/storage-usage").json();
        usage.mailboxUsedBytes = body.value("usedBytes", std::uint64_t{0});
        usage.mailboxQuotaBytes = body.value("quotaBytes", std::uint64_t{0});
        usage.mailboxOk = true;
    } catch (const std::exception& error) {
        // Unreachable / unauthorized: leave the mailbox half stale (ok=false).
        bazarish::log::warn("storage usage unavailable: {}", error.what());
    }
    return usage;
}



ContactInfo Client::fetchCard(const Descriptor& descriptor, const FetchTransport& transport)
{
    // The query names the fingerprint and hands back the descriptor's view
    // capability, and travels in the clear: the transport dials the destination
    // directly over I2P, whose stream is already encrypted and authenticated to
    // it, and no relayed path is allowed - that would tell our own server who is
    // being added.
    const FetchOutcome outcome = transport(descriptor.dest, "card",
        cardQueryBytes(CardFetchQuery{descriptor.fingerprint, descriptor.view}));
    if (!outcome.ok) {
        // The one answer for "no such user here" and "that is not the capability
        // I issued": from where the asker stands, both mean the same thing.
        throw std::runtime_error("that invite is out of date - ask for a new one");
    }

    ContactInfo info;
    info.card = ContactCard::verify(outcome.sealed);
    // The fingerprint is the trust anchor: the card is user-signed, so a wrong
    // server can only withhold, never forge a card for someone else's fingerprint.
    if (info.card.fingerprint() != descriptor.fingerprint) {
        throw std::runtime_error("fetched card is for a different fingerprint");
    }
    validateB32I2pHost(info.card.dest);
    return info;
}

Descriptor Client::resolveAlias(const std::string& alias, const ResolverCoordinate& resolver,
    const std::int64_t now, const FetchTransport& transport)
{
    // Seal the query (which alias) to the resolver's serving key so a relay on
    // the proxy path cannot read it; the response is sealed to a fresh ephemeral
    // key only we hold.
    const Key ephemeral = Key::generateSealing();
    const ResolveQuery query{alias, ephemeral.publicDer()};
    const std::string queryJson = toJson(query).dump();
    const Bytes sealedQuery = cms::seal(
        Bytes(queryJson.begin(), queryJson.end()), Key::fromPublicDer(resolver.sealingKeyDer));

    const FetchOutcome outcome = transport(resolver.dest, "resolve", sealedQuery);
    if (!outcome.ok) {
        throw std::runtime_error("alias resolve failed: "
            + (outcome.errorCode.empty() ? std::string("ALIAS_UNKNOWN") : outcome.errorCode));
    }
    const Bytes responseBytes = cms::unseal(outcome.sealed, ephemeral);
    const ResolveResponse fetched
        = resolveResponseFromJson(nlohmann::json::parse(responseBytes));

    // Verify the signature chain (record -> delegated key -> hardcoded root) and
    // that the record is for the alias we asked for. This is the integrity
    // anchor: even a malicious relay can only withhold, never forge a binding.
    const ResolveRecord record = verifyResolveRecord(
        fetched.recordDer, fetched.delegationDer, resolver.rootFingerprint, now);
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
    // The dest is empty while a personal destination is still building or has
    // gone offline; only validate (and later publish) a present address.
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

void Client::registerTokens(const std::vector<Bytes>& tokens)
{
    nlohmann::json encoded = nlohmann::json::array();
    for (const Bytes& token : tokens) {
        encoded.push_back(toBase64(token));
    }
    api_.postJson("/v1/messaging/tokens", {{"tokens", encoded}});
}

void Client::revokeTokens(const Bytes& mask)
{
    // The server takes the mask and answers at once; the sweep it schedules runs
    // on the node's own time, so a correspondent's tokens go away shortly rather
    // than instantly.
    api_.postJson("/v1/messaging/tokens/revoke", {{"mask", toBase64(mask)}});
}


std::vector<PendingEntry> Client::waitForPending(const int waitSeconds)
{
    // The read timeout outlasts the wait: the answer comes when the wait ends,
    // and the transport must not give up first.
    constexpr int kReadSlackSeconds = 20;
    const ApiResponse response = api_.getWaiting(
        kEventsPath, "wait=" + std::to_string(waitSeconds), waitSeconds + kReadSlackSeconds);
    const nlohmann::json body = response.json();
    std::vector<PendingEntry> entries;
    for (const nlohmann::json& entry : body.at("pending")) {
        entries.push_back(
            {entry.at("id").get<std::string>(), entry.at("class").get<std::string>()});
    }
    // A poll that waited and heard nothing says nothing: it happens all day and
    // would be the only thing the connection log ever showed.
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
    // Half a SHA-256 is what the id has always been the size of; the other half
    // adds nothing to a name.
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
