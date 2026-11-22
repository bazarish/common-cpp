// Bazarish project (c) 2026
#include "Client.hpp"
#include "LinkFailure.hpp"

#include "ResolverAsk.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/Devices.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/ResolvePuzzle.hpp>
#include <bazarish/ResolverChannel.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <ctime>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

namespace bazarish::client {

namespace {

}  // namespace

namespace {

// RFC 8259: a control character is written as \u00XX.
constexpr unsigned char kFirstPrintable = 0x20;
constexpr std::string_view kControlEscape = "\\u00";
constexpr char kHexDigits[] = "0123456789abcdef";
constexpr unsigned kNibbleBits = 4;
constexpr unsigned char kNibbleMask = 0x0f;

constexpr std::size_t kQuoteBytes = 2;
constexpr std::size_t kEscapedPairBytes = 2;
constexpr std::size_t kHexPerByte = 2;

std::size_t quotedLength(const ByteView value)
{
    std::size_t length = kQuoteBytes;
    for (const unsigned char c : value) {
        if (c == '"' || c == '\\') {
            length += kEscapedPairBytes;
        } else if (c < kFirstPrintable) {
            length += kControlEscape.size() + kHexPerByte;
        } else {
            ++length;
        }
    }
    return length;
}

unsigned char* writeQuoted(const ByteView value, unsigned char* at)
{
    *at++ = '"';
    for (const unsigned char c : value) {
        if (c == '"' || c == '\\') {
            *at++ = '\\';
            *at++ = c;
        } else if (c < kFirstPrintable) {
            at = std::copy(kControlEscape.begin(), kControlEscape.end(), at);
            *at++ = static_cast<unsigned char>(kHexDigits[c >> kNibbleBits]);
            *at++ = static_cast<unsigned char>(kHexDigits[c & kNibbleMask]);
        } else {
            *at++ = c;
        }
    }
    *at++ = '"';
    return at;
}

constexpr std::string_view kTransientField = "{\"transient\":";
constexpr std::string_view kExpiresField = ",\"expiresUnix\":";
constexpr std::string_view kSealingKeyField = ",\"sealingKey\":";
constexpr std::string_view kSigningKeyField = ",\"signingKey\":";
constexpr std::string_view kObjectEnd = "}";

unsigned char* writeText(const std::string_view text, unsigned char* at)
{
    return std::copy(text.begin(), text.end(), at);
}

// The delegation carries the address's private keys, so its body is written straight into a wiped buffer.
SecretBytes delegationBody(const Bytes& transient, const std::int64_t expiresUnix, const AddressKeys& keys)
{
    const SecretBytes transientB64 = secretBase64(transient);
    const std::string expires = std::to_string(expiresUnix);
    const bool withKeys = !transient.empty();
    std::size_t total = kTransientField.size() + quotedLength(transientB64.bytes()) + kExpiresField.size()
        + expires.size() + kObjectEnd.size();
    if (withKeys) {
        total += kSealingKeyField.size() + quotedLength(keys.sealingPem.bytes()) + kSigningKeyField.size()
            + quotedLength(keys.signingPem.bytes());
    }
    SecretBytes body(total);
    unsigned char* at = writeText(kTransientField, body.data());
    at = writeQuoted(transientB64.bytes(), at);
    at = writeText(kExpiresField, at);
    at = writeText(expires, at);
    if (withKeys) {
        at = writeText(kSealingKeyField, at);
        at = writeQuoted(keys.sealingPem.bytes(), at);
        at = writeText(kSigningKeyField, at);
        at = writeQuoted(keys.signingPem.bytes(), at);
    }
    writeText(kObjectEnd, at);
    return body;
}

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

constexpr char kI2pStatusPath[] = "/v1/account/i2p-status";
constexpr char kOverviewPath[] = "/v1/messaging/overview";
constexpr char kSinceQuery[] = "&since=";

std::string heldSince(const std::string& since)
{
    return std::string(kEventsHoldQuery) + kSinceQuery + since;
}

I2pDestStatus i2pStatusOf(const nlohmann::json& body)
{
    I2pDestStatus status;
    status.approval = body.value("approval", std::string());
    status.registrationMessage = body.value("registrationMessage", std::string());
    status.transientExpires = body.value("transientExpires", std::int64_t{0});
    return status;
}

MailboxUsage usageOf(const nlohmann::json& body)
{
    return {body.at("usedBytes").get<std::uint64_t>(), body.at("quotaBytes").get<std::uint64_t>()};
}

Bytes cardQueryBytes(const CardFetchQuery& query)
{
    const std::string text = toJson(query).dump();
    return Bytes(text.begin(), text.end());
}

}  // namespace

Client::Client(DeviceCredential credential, ServerEndpoint endpoint,
    std::filesystem::path i2pDataDir)
    : credential_(std::move(credential))
    , api_(credential_, std::move(endpoint), std::move(i2pDataDir))
{
    api_.setWireLog(log_);
}

WireLog& Client::wireLog()
{
    return *log_;
}

std::shared_ptr<WireLog> Client::wireLogHandle() const
{
    return log_;
}

void Client::shareWireLog(std::shared_ptr<WireLog> log)
{
    log_ = std::move(log);
    api_.setWireLog(log_);
}

const DeviceCredential& Client::credential() const
{
    return credential_;
}

const std::string& Client::deviceId() const
{
    return credential_.device();
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

bool Client::serverBehindFacadeDown() const
{
    return api_.serverBehindFacadeDown();
}

LinkFailure Client::linkFailure() const
{
    return api_.linkFailure();
}

bool Client::facadePublishedAnew()
{
    return api_.facadePublishedAnew();
}

void Client::liftStandOff()
{
    api_.liftStandOff();
}

void Client::setAccountLabel(std::string accountLabel)
{
    api_.setAccountLabel(std::move(accountLabel));
}

void Client::releaseI2pLink()
{
    api_.releaseI2pLink();
}

void Client::close()
{
    api_.close();
}

PublishResult Client::publishCard(const ContactCard& content, const Bytes& cardKey,
    const DestinationInfo& serving, const std::int64_t notBefore)
{
    validateB33I2pHost(serving.dest);
    ContactCard signedCard = content;
    signedCard.issuedAt = std::max(nowSeconds(), notBefore + 1);
    signedCard.dest = serving.dest;
    signedCard.servingSealingKeyDer = serving.servingSealingKeyDer;
    const Bytes card = signedCard.issue(credential_.signing());
    const nlohmann::json answer = api_.postJson(
        "/v1/account/card", {{"card", toBase64(card)}, {"cardKey", linkKeyText(cardKey)}}).json();

    PublishResult result;
    result.approvalPending = answer.at("approval").get<std::string>() == kApprovalPending;
    result.registrationMessage = answer.at("registrationMessage").get<std::string>();
    result.cardDer = card;
    result.dest = serving.dest;
    result.servingSealingKeyDer = serving.servingSealingKeyDer;
    return result;
}

void Client::closeAccount()
{
    api_.del("/v1/account/registration");
}

void Client::registerHere()
{
    (void)api_.postJson("/v1/account/registration", nlohmann::json::object()).json();
}

DestinationInfo Client::sendI2pTransient(
    const Bytes& transient, const std::int64_t expiresUnix, const AddressKeys& keys)
{
    const nlohmann::json body
        = api_.postSecret("/v1/account/i2p-dest", delegationBody(transient, expiresUnix, keys)).json();
    DestinationInfo info;
    info.dest = body.value("dest", std::string());
    return info;
}

I2pDestStatus Client::i2pStatus()
{
    return i2pStatusOf(api_.get(kI2pStatusPath).json());
}

I2pDestStatus Client::awaitApprovalChange(const std::string& approval)
{
    return i2pStatusOf(
        api_.getWaiting(kI2pStatusPath, heldSince(approval), kNoReadDeadline).json());
}

AccountOverview Client::overview(const std::string& since)
{
    const ApiResponse response = since.empty()
        ? api_.get(kOverviewPath)
        : api_.getWaiting(kOverviewPath, heldSince(since), kNoReadDeadline);
    return overviewFromJson(response.json());
}

nlohmann::json overviewToJson(const AccountOverview& overview)
{
    nlohmann::json clients = nlohmann::json::array();
    for (const OverviewDevice& device : overview.devices) {
        clients.push_back(
            {{"device", device.device}, {"current", device.current}, {"queue", device.queued}});
    }
    return {
        {"version", overview.version},
        {"dest", overview.dest},
        {"state", overview.state},
        {"transientExpires", overview.transientExpires},
        {"usedBytes", overview.usage.usedBytes},
        {"quotaBytes", overview.usage.quotaBytes},
        {"clients", clients},
    };
}

AccountOverview overviewFromJson(const nlohmann::json& body)
{
    AccountOverview overview;
    overview.version = body.at("version").get<std::string>();
    overview.dest = body.at("dest").get<std::string>();
    overview.state = body.at("state").get<std::string>();
    overview.transientExpires = body.at("transientExpires").get<std::int64_t>();
    overview.usage = usageOf(body);
    for (const nlohmann::json& entry : body.at("clients")) {
        overview.devices.push_back({entry.at("device").get<std::string>(),
            entry.at("current").get<bool>(), entry.at("queue").get<std::size_t>()});
    }
    if (!overview.dest.empty()) {
        validateB33I2pHost(overview.dest);
    }
    return overview;
}

ContactInfo Client::fetchCard(const Descriptor& descriptor, const FetchTransport& transport)
{
    const FetchOutcome outcome = transport(descriptor.dest, "card",
        KeyedSeal(descriptor.cardKey, kCardRequestLabel)
            .seal(cardQueryBytes(CardFetchQuery{descriptor.fingerprint})));
    if (!outcome.ok) {
        std::string reason = "the contact's server refused the card: ";
        reason += outcome.errorCode;
        throw LinkError(LinkFailure::eServerRefused, reason);
    }
    const std::optional<SecretBytes> cardDer
        = KeyedSeal(descriptor.cardKey, kCardReplyLabel).open(outcome.sealed);
    if (!cardDer.has_value()) {
        throw LinkError(
            LinkFailure::eServerMalformed, "the card came back sealed under another key");
    }

    ContactInfo info;
    try {
        info.card = ContactCard::verify(cardDer->bytes());
        validateB33I2pHost(info.card.dest);
    } catch (const std::exception& error) {
        std::string reason = "the fetched card does not read: ";
        reason += error.what();
        throw LinkError(LinkFailure::eServerMalformed, reason);
    }
    info.cardKey = descriptor.cardKey;
    if (info.card.fingerprint() != descriptor.fingerprint) {
        throw LinkError(
            LinkFailure::eServerMalformed, "fetched card is for a different fingerprint");
    }
    return info;
}

Descriptor Client::resolveAlias(const AliasQuery& alias, const ResolverCoordinate& resolver,
    const std::int64_t now, const FetchTransport& transport, const std::function<void()>& solving)
{
    ResolveQuery query{alias.name, alias.word, {}, 0};
    const auto ask = [&resolver, &transport, now](const ResolveQuery& asked) {
        const std::string queryJson = toJson(asked).dump();
        return askResolver(
            resolver, transport, kResolveOp, Bytes(queryJson.begin(), queryJson.end()), now);
    };
    FetchOutcome outcome = ask(query);
    if (!outcome.ok && outcome.errorCode == kProofRequiredCode) {
        std::uint32_t bits = 0;
        try {
            const nlohmann::json challenge = parseJson(outcome.refusal);
            bits = challenge.at("bits").get<std::uint32_t>();
            query.stamp = challenge.at("stamp").get<std::string>();
        } catch (const std::exception& error) {
            std::string reason = "the alias registry's puzzle does not read: ";
            reason += error.what();
            throw LinkError(LinkFailure::eServerMalformed, reason);
        }
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
        std::string reason = "the alias registry refused the lookup: ";
        reason += code;
        throw LinkError(LinkFailure::eServerRefused, reason);
    }
    std::optional<ResolveRecord> record;
    try {
        const ResolveResponse fetched = resolveResponseFromJson(parseJson(outcome.sealed));
        record = verifyResolveRecord(fetched.recordDer, fetched.delegationDer,
            fetched.aliasCertDer, resolver.rootFingerprint, now);
    } catch (const std::exception& error) {
        std::string reason = "the alias registry's record does not read: ";
        reason += error.what();
        throw LinkError(LinkFailure::eServerMalformed, reason);
    }
    if (record->alias != alias.name) {
        throw LinkError(
            LinkFailure::eServerMalformed, "resolver returned a record for a different alias");
    }
    return record->descriptor;
}

DestinationInfo Client::myDestination()
{
    const ApiResponse response = api_.get("/v1/messaging/destination");
    const nlohmann::json body = response.json();
    DestinationInfo info;
    info.dest = body.at("dest").get<std::string>();
    if (!info.dest.empty()) {
        validateB33I2pHost(info.dest);
    }
    return info;
}

void Client::registerThisDevice(const std::string& install)
{
    api_.postJson("/v1/messaging/clients", {{"install", install}});
}

void Client::forgetDeviceMail(const std::string& device)
{
    if (!isDeviceId(device)) {
        throw std::invalid_argument("not a device id: " + device);
    }
    api_.del("/v1/messaging/clients/" + device);
}

void Client::registerPasses(const std::vector<Bytes>& handles)
{
    nlohmann::json encoded = nlohmann::json::array();
    for (const Bytes& handle : handles) {
        encoded.push_back(toBase64(handle));
    }
    api_.postJson("/v1/messaging/passes", {{"passes", encoded}});
}

void Client::revokePasses(const std::vector<Bytes>& handles)
{
    nlohmann::json encoded = nlohmann::json::array();
    for (const Bytes& handle : handles) {
        encoded.push_back(toBase64(handle));
    }
    api_.postJson("/v1/messaging/passes/revoke", {{"passes", encoded}});
}

std::vector<PendingEntry> Client::waitForPending(
    const MailWait wait, const std::vector<std::string>& deferred)
{
    const bool held = wait == MailWait::eHeld;
    std::string query = held ? kEventsHoldQuery : "";
    if (held && !deferred.empty()) {
        query += std::string("&") + kEventsDeferredKey + "=";
        for (std::size_t i = 0; i < deferred.size(); ++i) {
            if (i > 0) {
                query += kEventsDeferredSeparator;
            }
            query += deferred[i];
        }
    }
    const ApiResponse response = api_.getWaiting(kEventsPath, query,
        held ? kNoReadDeadline : ApiClient::kDefaultReadTimeoutSeconds);
    const nlohmann::json body = response.json();
    const std::vector<PendingEntry> entries = pendingEntries(body.at("pending"));
    lastMailboxUsage_ = usageOf(body);
    if (!entries.empty()) {
        log_->record({0, false, "poll: " + std::to_string(entries.size()) + " waiting", "200", {}});
    }
    return entries;
}

std::optional<MailboxUsage> Client::lastMailboxUsage() const
{
    return lastMailboxUsage_;
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
        = parseCbor(api_.postJson("/v1/messaging/fetch", {{"ids", ids}}).body);
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

void Client::submitSelf(const std::string& deliveryId, const Bytes& payload,
    const std::string& kind, const std::string& toDevice)
{
    api_.postJson("/v1/messaging/self",
        {{"deliveryId", deliveryId}, {"payload", toBase64(payload)}, {"to", toDevice}},
        ApiClient::kDefaultReadTimeoutSeconds, kind);
}

}  // namespace bazarish::client
