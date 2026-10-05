// Bazarish project (c) 2026
#include "Session.hpp"

#include "LoginSigner.hpp"

#include "AccountDb.hpp"

#include "Authorship.hpp"
#include "FederationFetch.hpp"
#include "I2pKeys.hpp"
#include "I2pRouter.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Descriptor.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Padding.hpp>
#include <bazarish/Pass.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Portal.hpp>
#include <bazarish/Reactions.hpp>
#include <bazarish/I2pAddress.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <set>
#include <stdexcept>
#include <thread>

namespace bazarish::client {

constexpr std::chrono::milliseconds kSlowStretch{200};

namespace {

constexpr std::size_t kPassPrefixChars = 12;

constexpr std::size_t kTransferAskBytes = 8;

}  // namespace

namespace {

bool isBlank(const std::string& text)
{
    return text.find_first_not_of(" \t\r\n") == std::string::npos;
}

const char* const kTypeFile = "file";
const char* const kTypeImage = "image";
const char* const kTypeVoice = "voice";
const char* const kCallOpeningStage = "Opening the audio path";
constexpr std::size_t kDeliveryIdBytes = 16;
constexpr std::size_t kContactBookChunkBytes = 128 * 1024;
constexpr std::size_t kRequestIdBytes = 8;

// How often a device asks the name service after its own names, and how widely that ask is spread.
constexpr std::int64_t kAliasStatusIntervalSeconds = 24 * 3600;
constexpr std::int64_t kAliasStatusJitterSeconds = 6 * 3600;
static_assert(kAliasStatusIntervalSeconds + kAliasStatusJitterSeconds
        < bazarish::kAliasStatusValiditySeconds,
    "a relayed status must still be valid when the slowest device wakes");

std::uint64_t randomBelow(const std::uint64_t bound)
{
    if (bound == 0) {
        return 0;
    }
    const bazarish::Bytes bytes = bazarish::randomBytes(sizeof(std::uint64_t));
    std::uint64_t value = 0;
    for (const std::uint8_t byte : bytes) {
        value = (value << 8) | byte;
    }
    return value % bound;
}
constexpr std::size_t kShortFingerprintChars = 8;
constexpr const char* kPendingAddsKey = "pending-contact-adds";

constexpr std::size_t kDeliveryIdSeedBytes = 32;
const char* const kCallDeliveredStage = "Invitation delivered";
const char* const kCallAlertingStage = "Their device is ringing";

namespace fs = std::filesystem;

fs::path i2pDirFor(const fs::path& accountFile)
{
    return accountFile.parent_path().parent_path() / "i2p";
}

constexpr std::int64_t kInviteDeliveryTimeoutMs = 120000;
constexpr std::int64_t kMediaSilenceTimeoutMs = 20000;
constexpr std::int64_t kRingTimeoutMs = 60000;
constexpr std::size_t kEndedCallsRemembered = 32;

constexpr int kMessageFormatVersion = 1;
constexpr int kBundleFormatVersion = 1;

constexpr std::int64_t kSecondsPerDay = 24 * 3600;

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

std::int64_t nowMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

constexpr std::size_t kAvatarMaxBytes = 500 * 1024;

void applyBootstrap(Contact& contact, const nlohmann::json& bootstrap)
{
    if (bootstrap.contains("sealing")) {
        contact.sealingPublicB64 = bootstrap.at("sealing").get<std::string>();
    }
    if (bootstrap.contains("dest")) {
        contact.dest = bootstrap.at("dest").get<std::string>();
        validateB32I2pHost(contact.dest);
    }
    if (bootstrap.contains("servingKey")) {
        contact.servingSealingB64 = bootstrap.at("servingKey").get<std::string>();
    }
    if (bootstrap.contains("view")) {
        contact.view = bootstrap.at("view").get<std::string>();
    }
    if (!bootstrap.contains("pass")) {
        return;
    }
    const std::string offered = bootstrap.at("pass").get<std::string>();
    if (offered.empty() || offered == contact.sendPass) {
        return;
    }
    contact.sendPass = offered;
    bazarish::log::info(
        "delivery pass for {} accepted", bazarish::log::redact(contact.dest));
}

void writeFileText(const fs::path& path, const std::string& text)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("failed to open " + path.string());
    }
    out << text;
    if (!out) {
        throw std::runtime_error("failed to write " + path.string());
    }
}

nlohmann::json keyboardToJson(const InlineKeyboard& keyboard)
{
    nlohmann::json rows = nlohmann::json::array();
    for (const std::vector<InlineButton>& row : keyboard) {
        nlohmann::json jsonRow = nlohmann::json::array();
        for (const InlineButton& button : row) {
            nlohmann::json jsonButton = {{"text", button.text}};
            if (!button.data.empty()) {
                jsonButton["data"] = button.data;
            } else if (!button.command.empty()) {
                jsonButton["command"] = button.command;
            }
            jsonRow.push_back(std::move(jsonButton));
        }
        rows.push_back(std::move(jsonRow));
    }
    return rows;
}

constexpr int kServeWindowSeconds = 30 * 60;
constexpr std::int64_t kFileRequestFreshnessMs = 5 * 60 * 1000;
constexpr int kPublishWaitSeconds = 180;
constexpr int kPublishPollSeconds = 2;

std::string guessMime(const fs::path& path)
{
    const std::string ext = path.extension().string();
    if (ext == ".jpg" || ext == ".jpeg") {
        return "image/jpeg";
    }
    if (ext == ".png") {
        return "image/png";
    }
    if (ext == ".gif") {
        return "image/gif";
    }
    if (ext == ".pdf") {
        return "application/pdf";
    }
    if (ext == ".txt") {
        return "text/plain";
    }
    if (ext == ".ogg" || ext == ".opus") {
        return "audio/ogg";
    }
    if (ext == ".mp3") {
        return "audio/mpeg";
    }
    return "application/octet-stream";
}

// The sealed message body, as bytes.
bool echoesToOwnDevices(const std::string& type)
{
    static const std::set<std::string> kEchoed{
        "text", "image", "voice", "edit", "delete", "reaction", "chat.clear"};
    return kEchoed.find(type) != kEchoed.end();
}

constexpr std::size_t kSealOverheadAllowance = 8 * 1024;

Bytes encodedBody(const nlohmann::json& inner)
{
    return padToLadder(
        nlohmann::json::to_cbor(inner), kMaxMessagePayloadBytes - kSealOverheadAllowance);
}

nlohmann::json decodedBody(const Bytes& bytes)
{
    return nlohmann::json::from_cbor(unpadFromLadder(bytes));
}

bazarish::i2p::Router& routerForAdd(const bool i2pEnabled)
{
    if (!i2pEnabled) {
        throw std::runtime_error("adding a contact needs I2P, and it is switched off");
    }
    bazarish::i2p::Router* const router = sharedI2pRouterIfRunning();
    if (router == nullptr || !router->ready()) {
        throw std::runtime_error(
            "adding a contact needs the I2P router; it is still building tunnels");
    }
    return *router;
}

void addReplyAndForward(
    nlohmann::json& inner, const std::string& replyTo, const bool forwarded)
{
    if (!replyTo.empty()) {
        inner["replyTo"] = replyTo;
    }
    if (forwarded) {
        inner["forwarded"] = true;
    }
}

}  // namespace

std::string inlineKeyboardJson(const InlineKeyboard& keyboard)
{
    return keyboardToJson(keyboard).dump();
}

Session::Session(fs::path accountFile, std::unique_ptr<Client> client, Key sealingKey,
    std::map<std::string, Contact> contacts)
    : accountPath_(std::move(accountFile))
    , client_(std::move(client))
    , sealingKey_(std::move(sealingKey))
    , contacts_(std::move(contacts))
{
}

bazarish::i2p::Router& Session::i2pRouter() const
{
    const fs::path dataDir = i2pDirFor(accountPath_);
    setReseedUrls(client_->endpoint().reseeds);
    return sharedI2pRouter(dataDir);
}

Session::~Session() = default;
Session::Session(Session&&) noexcept = default;
Session& Session::operator=(Session&&) noexcept = default;

Session Session::create(
    const fs::path& accountFile, const std::string& passphrase, const std::string& name)
{
    auto db = std::make_unique<AccountDb>(accountFile, passphrase);

    Identity identity = Identity::generate();
    db->putText("identity.pem", identity.privatePem());

    Key sealing = Key::generateSealing();
    db->putText("sealing.pem", sealing.privatePem());

    const std::string clientId = toHex(randomBytes(8));
    const bool encrypted = !passphrase.empty();
    const std::string fingerprint = identity.fingerprint();

    const ServerEndpoint endpoint;

    const std::string deliveryIdSeed = toHex(randomBytes(kDeliveryIdSeedBytes));
    const std::string deliverySecret = toHex(randomBytes(kDeliverySecretSize));
    const nlohmann::json meta = {
        {"clientId", clientId},
        {"deliveryIdSeed", deliveryIdSeed},
        {"deliverySecret", deliverySecret},
        {"name", name},
        {"fingerprint", fingerprint},
        {"endpoint",
            {
                {"serverFingerprint", endpoint.serverFingerprint},
                {"facades", nlohmann::json::array()},
            }},
        {"encrypted", encrypted},
    };
    db->putText("meta", meta.dump(2));

    auto client = std::make_unique<Client>(
        std::move(identity), clientId, endpoint, i2pDirFor(accountFile));
    Session session(accountFile, std::move(client), std::move(sealing), {});
    session.db_ = std::move(db);
    session.encrypted_ = encrypted;
    session.passphrase_ = passphrase;
    session.name_ = name;
    session.deliveryIdSeed_ = deliveryIdSeed;
    session.deliverySecret_ = fromHex(deliverySecret);
    session.client_->setDestinationOwner(session.destinationOwner());
    return session;
}

Session Session::create(const fs::path& accountFile, const ServerEndpoint& endpoint,
    const std::string& passphrase)
{
    Session session = create(accountFile, passphrase);
    session.connectServer(endpoint);
    return session;
}

void Session::connectServer(const ServerEndpoint& endpoint)
{
    // Rebind the transport to the new server, reusing the identity and client id.
    client_ = std::make_unique<Client>(
        Identity::fromPrivatePem(client_->identity().privatePem()), client_->clientId(), endpoint,
        i2pDirFor(accountPath_));
    client_->setDestinationOwner(destinationOwner());
    persistMeta();
}

bool Session::isConnected() const
{
    return !client_->endpoint().facades.empty();
}

const ServerEndpoint& Session::endpoint() const
{
    return client_->endpoint();
}

std::string Session::activeFacadeUrl() const
{
    return client_->activeFacadeUrl();
}

std::vector<std::string> Session::facadeUrls() const
{
    std::vector<std::string> urls;
    for (const Facade& facade : client_->endpoint().facades) {
        urls.push_back(facadeToUrl(facade));
    }
    return urls;
}

Session Session::open(const fs::path& accountFile, const std::string& passphrase)
{
    auto db = std::make_unique<AccountDb>(accountFile, passphrase);
    const nlohmann::json meta = nlohmann::json::parse(db->text("meta"));
    ServerEndpoint endpoint;
    const nlohmann::json& endpointJson = meta.at("endpoint");
    endpoint.serverFingerprint = endpointJson.at("serverFingerprint").get<std::string>();
    for (const nlohmann::json& url : endpointJson.at("facades")) {
        endpoint.facades.push_back(parseFacadeUrl(url.get<std::string>()));
    }
    if (endpointJson.contains("reseeds")) {
        for (const nlohmann::json& url : endpointJson.at("reseeds")) {
            endpoint.reseeds.push_back(url.get<std::string>());
        }
    }

    const bool encrypted = meta.value("encrypted", false);

    Identity identity = Identity::fromPrivatePem(db->text("identity.pem"));
    Key sealing = Key::fromPrivatePem(db->text("sealing.pem"));
    const std::string clientId = meta.at("clientId").get<std::string>();

    std::map<std::string, Contact> contacts;
    if (db->has("contacts")) {
        const nlohmann::json stored = nlohmann::json::parse(db->text("contacts"));
        for (const auto& [fingerprint, entry] : stored.items()) {
            Contact contact;
            contact.sealingPublicB64 = entry.at("sealingPublicB64").get<std::string>();
            contact.dest = entry.at("dest").get<std::string>();
            contact.servingSealingB64 = entry.at("servingSealingB64").get<std::string>();
            contact.identityClassicalB64 = entry.value("identityClassicalB64", std::string());
            contact.identityPqB64 = entry.value("identityPqB64", std::string());
            contact.sendPass = entry.value("sendPass", std::string());
            contact.issuedToThem = entry.at("issuedToThem").get<bool>();
            contact.displayName = entry.value("displayName", std::string());
            contact.avatarMime = entry.value("avatarMime", std::string());
            contact.avatarSentToPeer = entry.value("avatarSentToPeer", false);
            contact.view = entry.value("view", std::string());
            contact.sharingRefused = entry.value("sharingRefused", false);
            contact.notifications = entry.value("notifications", true);
            contact.allowCalls = entry.value("allowCalls", true);
            contacts.emplace(fingerprint, std::move(contact));
        }
    }

    std::set<std::string> pendingRevokes;
    if (db->has("pass-revokes")) {
        for (const nlohmann::json& entry : nlohmann::json::parse(db->text("pass-revokes"))) {
            pendingRevokes.insert(entry.get<std::string>());
        }
    }

    std::set<std::string> blocked;
    if (db->has("blocked")) {
        for (const nlohmann::json& entry : nlohmann::json::parse(db->text("blocked"))) {
            blocked.insert(entry.get<std::string>());
        }
    }

    auto client = std::make_unique<Client>(
        std::move(identity), clientId, endpoint, i2pDirFor(accountFile));
    Session session(accountFile, std::move(client), std::move(sealing), std::move(contacts));
    session.db_ = std::move(db);
    session.blocked_ = std::move(blocked);
    session.pendingPassRevokes_ = std::move(pendingRevokes);
    session.acceptCalls_ = meta.value("acceptCalls", true);
    session.sendReceipts_ = meta.value("sendReceipts", true);
    session.contactsAskedBy_
        = meta.value("contactsAskedBy", std::vector<std::string>());
    session.cardB64_ = meta.value("card", std::string{});
    session.view_ = meta.value("view", std::string{});
    for (const nlohmann::json& held : meta.value("aliasNames", nlohmann::json::array())) {
        session.aliasNames_.push_back(
            Session::AliasHolding{held.value("alias", std::string()),
                held.value("notAfter", std::int64_t{0}), held.value("autoRenew", true),
                held.value("bindingWanted", false), held.value("bound", false)});
    }
    session.aliasCheckAfter_ = meta.value("aliasCheckAfter", std::int64_t{0});
    session.aliasStatusAt_ = meta.value("aliasStatusAt", std::int64_t{0});
    session.aliasDepositCovers_ = meta.value("aliasDepositCovers", true);
    session.aliasPushedDest_ = meta.value("aliasPushedDest", std::string{});
    session.aliasPushedView_ = meta.value("aliasPushedView", std::string{});
    session.sharingAllowed_ = meta.value("sharingAllowed", true);
    session.delegationDays_ = meta.value("delegationDays", kDefaultDelegationDays);
    session.deliveryIdSeed_ = meta.value("deliveryIdSeed", std::string());
    if (session.deliveryIdSeed_.empty()) {
        throw std::runtime_error(
            "this account was written before delivery ids were seeded and cannot be read;"
            " create it again");
    }
    const std::string deliverySecret = meta.value("deliverySecret", std::string());
    if (deliverySecret.empty()) {
        session.deliverySecret_ = randomBytes(kDeliverySecretSize);
        session.persistMeta();
        bazarish::log::warn("this account predates derived delivery passes: what it issued"
            " before now cannot be revoked, only what it issues from here");
    } else {
        session.deliverySecret_ = fromHex(deliverySecret);
    }
    if (!session.cardB64_.empty()) {
        const ContactCard card = ContactCard::verify(fromBase64(session.cardB64_));
        session.myDest_ = card.dest;
        if (!card.servingSealingKeyDer.empty()) {
            session.myServingKeyB64_ = toBase64(card.servingSealingKeyDer);
        }
    }
    session.encrypted_ = encrypted;
    session.passphrase_ = passphrase;
    session.name_ = meta.value("name", std::string{});
    if (isBlank(session.name_)) {
        session.name_ = accountFile.stem().string();
        session.persistMeta();
    }
    session.client_->setDestinationOwner(session.destinationOwner());
    session.loadSentFiles();

    const auto loadBlob = [&session](const std::string& name) -> Bytes {
        return session.db_->get(name).value_or(Bytes{});
    };
    session.i2pMaster_ = loadBlob("i2p-master");
    if (!session.i2pMaster_.empty()) {
        session.i2pAddress_ = i2pRoutingHost(session.i2pMaster_);
    }
    session.i2pTransient_ = loadBlob("i2p-transient");

    session.avatarMime_ = meta.value("avatarMime", std::string{});
    if (!session.avatarMime_.empty()) {
        session.avatar_ = loadBlob("avatar.self");
        if (session.avatar_.empty()) {
            session.avatarMime_.clear();
        }
    }
    for (auto& [contactFp, contact] : session.contacts_) {
        if (!contact.avatarMime.empty()) {
            contact.avatar = loadBlob("avatar-" + contactFp);
            if (contact.avatar.empty()) {
                contact.avatarMime.clear();
            }
        }
    }

    return session;
}

std::string Session::fingerprint() const
{
    return client_->identity().fingerprint();
}

const std::string& Session::displayName() const
{
    return name_;
}

void Session::setDisplayName(const std::string& name)
{
    if (isBlank(name)) {
        throw std::invalid_argument("an account needs a name");
    }
    if (name.size() > kMaxAccountNameBytes) {
        throw std::invalid_argument("an account name may be at most "
            + std::to_string(kMaxAccountNameBytes) + " bytes");
    }
    if (name == name_) {
        return;
    }
    name_ = name;
    client_->setDestinationOwner(destinationOwner());
    persistMeta();
    try {
        sendSelf({
            {"type", "device.account-name"},
            {"name", name},
        });
    } catch (const std::exception& error) {
        bazarish::log::warn("account-name self-sync failed: {}", error.what());
    }
}

const Bytes& Session::avatar() const
{
    return avatar_;
}

const std::string& Session::avatarMime() const
{
    return avatarMime_;
}

std::string Session::contactDisplayName(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    return found == contacts_.end() ? std::string() : found->second.displayName;
}

Bytes Session::contactAvatar(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    return found == contacts_.end() ? Bytes() : found->second.avatar;
}

bool Session::contactIsPending(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    return found != contacts_.end() && !found->second.issuedToThem;
}

bool Session::contactAcceptInFlight(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    return found != contacts_.end() && found->second.acceptInFlight;
}

std::string Session::sealingPublicB64() const
{
    return toBase64(sealingKey_.publicDer());
}

bool Session::hasContact(const std::string& peerFingerprint) const
{
    return contacts_.find(peerFingerprint) != contacts_.end();
}

std::vector<std::string> Session::contactFingerprints() const
{
    std::vector<std::string> fingerprints;
    fingerprints.reserve(contacts_.size());
    for (const auto& [fingerprint, contact] : contacts_) {
        (void)contact;
        fingerprints.push_back(fingerprint);
    }
    return fingerprints;
}

void Session::persistMeta() const
{
    const ServerEndpoint& endpoint = client_->endpoint();
    nlohmann::json facades = nlohmann::json::array();
    for (const Facade& facade : endpoint.facades) {
        facades.push_back(facadeToUrl(facade));
    }
    nlohmann::json reseeds = nlohmann::json::array();
    for (const std::string& reseed : endpoint.reseeds) {
        reseeds.push_back(reseed);
    }
    const nlohmann::json meta = {
        {"clientId", client_->clientId()},
        {"name", name_},
        {"fingerprint", client_->identity().fingerprint()},
        {"endpoint",
            {
                {"serverFingerprint", endpoint.serverFingerprint},
                {"facades", facades},
                {"reseeds", reseeds},
            }},
        {"card", cardB64_},
        {"deliveryIdSeed", deliveryIdSeed_},
        {"deliverySecret", toHex(deliverySecret_)},
        {"view", view_},
        {"sharingAllowed", sharingAllowed_},
        {"delegationDays", delegationDays_},
        {"encrypted", encrypted_},
        {"avatarMime", avatarMime_},
        {"acceptCalls", acceptCalls_},
        {"sendReceipts", sendReceipts_},
        {"contactsAskedBy", contactsAskedBy_},
        {"aliasNames", aliasNamesToJson()},
        {"aliasCheckAfter", aliasCheckAfter_},
        {"aliasStatusAt", aliasStatusAt_},
        {"aliasDepositCovers", aliasDepositCovers_},
        {"aliasPushedDest", aliasPushedDest_},
        {"aliasPushedView", aliasPushedView_},
    };
    db_->putText("meta", meta.dump(2));
}

nlohmann::json Session::aliasNamesToJson() const
{
    nlohmann::json held = nlohmann::json::array();
    for (const AliasHolding& holding : aliasNames_) {
        held.push_back({{"alias", holding.alias}, {"notAfter", holding.notAfter},
            {"autoRenew", holding.autoRenew}, {"bindingWanted", holding.bindingWanted},
            {"bound", holding.bound}});
    }
    return held;
}

nlohmann::json Session::contactsToJson() const
{
    nlohmann::json stored = nlohmann::json::object();
    for (const auto& [fingerprint, contact] : contacts_) {
        stored[fingerprint] = {
            {"sealingPublicB64", contact.sealingPublicB64},
            {"dest", contact.dest},
            {"servingSealingB64", contact.servingSealingB64},
            {"identityClassicalB64", contact.identityClassicalB64},
            {"identityPqB64", contact.identityPqB64},
            {"sendPass", contact.sendPass},
            {"issuedToThem", contact.issuedToThem},
            {"displayName", contact.displayName},
            {"avatarMime", contact.avatarMime},
            {"avatarSentToPeer", contact.avatarSentToPeer},
            {"view", contact.view},
            {"sharingRefused", contact.sharingRefused},
            {"notifications", contact.notifications},
            {"allowCalls", contact.allowCalls},
        };
    }
    return stored;
}

void Session::persistContacts() const
{
    db_->putText("contacts", contactsToJson().dump());
}

PortalInfo Session::serverPortalInfo()
{
    return client_->fetchPortalInfo();
}

void Session::registerAccount()
{
    requireSwitchedOn();
    PublishResult result;
    try {
        result = client_->publishCard(sealingKey_.publicDer(), ownRoutingHost(), currentCardIssuedAt());
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eDeliveryRejected) {
            throw;
        }
        reportConnectProgress(60, "Registering with this server");
        client_->registerHere();
        result = client_->publishCard(sealingKey_.publicDer(), ownRoutingHost(), currentCardIssuedAt());
    }
    reportConnectProgress(70, "Registered; registering this device");
    storeCard(result);
    client_->registerThisClient();

    reportConnectProgress(83, "Checking the address your server serves");
    if (!reconcileI2pAddress()) {
        bazarish::log::warn("this server serves an address this device has no keys for");
        return;
    }
    reportConnectProgress(85, "Publishing your own destination");
    try {
        publishRouting();
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eAccountPendingApproval) {
            throw;
        }
        approval_.pending = true;
        bazarish::log::info("account awaiting operator approval: no routing published yet");
    }
}

void Session::registerSelfHosted()
{
    PublishResult result;
    try {
        result = client_->publishCard(sealingKey_.publicDer(), {}, currentCardIssuedAt());
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eDeliveryRejected) {
            throw;
        }
        client_->registerHere();
        result = client_->publishCard(sealingKey_.publicDer(), {}, currentCardIssuedAt());
    }
    storeCard(result);
    client_->registerThisClient();
}

void Session::publishRouting()
{
    if (!hasI2pDestination()) {
        throw std::runtime_error("no user-owned I2P destination to publish");
    }
    if (cardB64_.empty()) {
        throw std::runtime_error("not registered: nothing to publish routing into");
    }
    const std::int64_t expires = renewI2pTransient(delegationDays_);
    reportConnectProgress(88, "Delegating your destination to the server");
    client_->sendI2pTransient(i2pTransientBase64(), expires);
    reportConnectProgress(92, "Publishing your contact card");
    storeCard(client_->publishCard(sealingKey_.publicDer(), ownRoutingHost(), currentCardIssuedAt()));
    reportConnectProgress(96, "Syncing your address to your other devices");
    try {
        syncI2pMasterToSelf();
    } catch (const std::exception& error) {
        bazarish::log::info("master not synced to this account's other devices: {}", error.what());
    }
    reportConnectProgress(98, "Telling the name service where you are");
    serviceAliasesAfterMove();
    approval_ = {};
}

void Session::storeCard(const PublishResult& result)
{
    cardB64_ = toBase64(result.cardDer);
    if (!result.view.empty()) {
        view_ = result.view;
    }
    myDest_ = result.dest;
    myServingKeyB64_
        = result.servingSealingKeyDer.empty() ? std::string() : toBase64(result.servingSealingKeyDer);
    persistMeta();
}

std::int64_t Session::currentCardIssuedAt() const
{
    if (cardB64_.empty()) {
        return 0;
    }
    try {
        return ContactCard::verify(fromBase64(cardB64_)).issuedAt;
    } catch (const std::exception& error) {
        log::warn("this account's own card will not read back: {}", error.what());
        return 0;
    }
}

std::string Session::ownRoutingHost() const
{
    return i2pAddress_;
}

void Session::persistSealedBlob(const std::string& name, const Bytes& blob) const
{
    db_->put(name, blob);
}

void Session::persistI2pBlob(const std::string& name, const Bytes& blob) const
{
    persistSealedBlob(name, blob);
}

std::string Session::ensureI2pDestination()
{
    if (i2pMaster_.empty()) {
        const I2pMasterKey master = generateI2pMaster();
        i2pMaster_ = master.privateKeys;
        i2pAddress_ = master.host;
        persistI2pBlob("i2p-master", i2pMaster_);
    }
    return i2pAddress_;
}

bool Session::hasI2pDestination() const
{
    return !i2pMaster_.empty();
}

std::string Session::i2pAddress() const
{
    return i2pAddress_;
}

void Session::deleteI2pDestination()
{
    i2pMaster_.clear();
    i2pTransient_.clear();
    i2pAddress_.clear();
    db_->erase("i2p-master");
    db_->erase("i2p-transient");
}

std::int64_t Session::renewI2pTransient(const int days)
{
    if (i2pMaster_.empty()) {
        throw std::runtime_error("no user-owned I2P destination to delegate");
    }
    i2pTransient_ = issueI2pOfflineKeys(i2pMaster_, days);
    persistI2pBlob("i2p-transient", i2pTransient_);
    return i2pDelegationExpires(i2pTransient_);
}

Bytes Session::i2pTransient() const
{
    return i2pTransient_;
}

std::string Session::i2pTransientBase64() const
{
    return i2pPrivateKeysBase64(i2pTransient_);
}

std::string Session::loadI2pDestination(const Bytes& privateKeysDat)
{
    if (!i2pMaster_.empty()) {
        throw std::runtime_error("a user-owned I2P destination is already configured");
    }
    const I2pMasterKey master = loadI2pMaster(privateKeysDat);
    i2pMaster_ = master.privateKeys;
    i2pAddress_ = master.host;
    persistI2pBlob("i2p-master", i2pMaster_);
    return i2pAddress_;
}

void Session::replaceI2pMaster(const Bytes& privateKeysDat)
{
    const I2pMasterKey master = loadI2pMaster(privateKeysDat);
    i2pMaster_ = master.privateKeys;
    i2pAddress_ = master.host;
    persistI2pBlob("i2p-master", i2pMaster_);
    i2pTransient_.clear();
    db_->erase("i2p-transient");
}

void Session::disableI2pDest()
{
    client_->sendI2pTransient(std::string(), 0);
    i2pTransient_.clear();
    db_->erase("i2p-transient");
}

bool Session::adoptI2pMasterFromOwnMailbox(const std::string& wantedHost)
{
    try {
        for (const PendingEntry& entry : client_->listPending()) {
            const Bytes blob = client_->fetchBlob(entry.id);
            const nlohmann::json body = decodedBody(cms::unseal(blob, sealingKey_));
            if (body.value("type", std::string()) != "device.i2p-master"
                || body.value("from", std::string()) != fingerprint()) {
                continue;
            }
            if (authorOf(body, knownKeysFor(fingerprint())) != fingerprint()) {
                continue;
            }
            const Bytes master = fromBase64(body.at("i2pMaster").get<std::string>());
            if (!wantedHost.empty() && i2pRoutingHost(master) != wantedHost) {
                continue;
            }
            loadI2pDestination(master);
            log::info("adopted this account's address from another of its devices");
            return true;
        }
    } catch (const std::exception& error) {
        log::warn("could not read this account's own mailbox for its address: {}",
            error.what());
    }
    return false;
}

void Session::askDevicesForI2pMaster(const std::string& servedHost)
{
    const nlohmann::json inner = envelope("device.i2p-master-request", toHex(randomBytes(16)), {
        {"device", client_->clientId()},
        {"host", servedHost},
    });
    submitSignedToSelf(inner, "device.i2p-master-request");
}

bool Session::reconcileI2pAddress()
{
    const std::string servedHost = [this]() {
        try {
            return client_->myDestination().dest;
        } catch (const std::exception& error) {
            log::info("server did not say which address it serves: {}", error.what());
            return std::string();
        }
    }();
    const std::string ourHost = i2pMaster_.empty() ? std::string() : i2pAddress_;

    if (servedHost.empty()) {
        ensureI2pDestination();
        return true;
    }
    if (!ourHost.empty() && servedHost == ourHost) {
        return true;
    }

    log::info("this server serves {}, this device holds {}", log::redact(servedHost),
        ourHost.empty() ? std::string("no address") : log::redact(ourHost));
    try {
        askDevicesForI2pMaster(servedHost);
    } catch (const std::exception& error) {
        log::info("could not ask this account's other devices for its address: {}", error.what());
    }
    if (adoptI2pMasterFromOwnMailbox(servedHost)) {
        return true;
    }
    if (addressDecision_) {
        addressDecision_(servedHost, ourHost);
    }
    return false;
}

void Session::publishThisDeviceAddress()
{
    ensureI2pDestination();
    publishRouting();
}

void Session::publishFreshAddress()
{
    i2pMaster_.clear();
    i2pAddress_.clear();
    i2pTransient_.clear();
    db_->erase("i2p-transient");
    ensureI2pDestination();
    publishRouting();
}

void Session::syncI2pMasterToSelf()
{
    if (i2pMaster_.empty() || myDest_.empty() || myServingKeyB64_.empty()) {
        return;
    }
    const nlohmann::json inner = envelope("device.i2p-master", toHex(randomBytes(16)), {
        {"i2pMaster", toBase64(i2pMaster_)},
    });
    submitSignedToSelf(inner, "device.i2p-master");
}

void Session::storeOwnAvatar(const Bytes& data, const std::string& mime)
{
    avatar_ = data;
    avatarMime_ = mime;
    if (avatar_.empty()) {
        db_->erase("avatar.self");
    } else {
        persistSealedBlob("avatar.self", avatar_);
    }
    persistMeta();
}

void Session::storeContactAvatar(
    const std::string& peerFingerprint, const Bytes& data, const std::string& mime)
{
    if (data.size() > kAvatarMaxBytes) {
        return;
    }
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        return;
    }
    found->second.avatar = data;
    found->second.avatarMime = mime;
    if (data.empty()) {
        db_->erase("avatar-" + peerFingerprint);
    } else {
        persistSealedBlob("avatar-" + peerFingerprint, data);
    }
    persistContacts();
}

void Session::syncAvatarToSelf()
{
    if (myDest_.empty() || myServingKeyB64_.empty()) {
        return;
    }
    const nlohmann::json inner = envelope("device.avatar", toHex(randomBytes(16)), {
        {"avatar", {{"mime", avatarMime_}, {"data", toBase64(avatar_)}}},
    });
    submitSignedToSelf(inner, "device.avatar");
}

void Session::syncContactNameToSelf(const std::string& peerFingerprint, const std::string& name)
{
    if (myDest_.empty() || myServingKeyB64_.empty()) {
        return;
    }
    const nlohmann::json inner = envelope("device.contact-name", toHex(randomBytes(16)), {
        {"peer", peerFingerprint},
        {"name", name},
    });
    submitSignedToSelf(inner, "device.contact-name");
}

std::string safeContactName(const std::string& proposed)
{
    std::string folded;
    folded.reserve(proposed.size());
    for (const char c : proposed) {
        folded.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(c))));
    }
    const std::size_t first = folded.find_first_not_of(" \t\r\n");
    const std::size_t last = folded.find_last_not_of(" \t\r\n");
    const std::string trimmed
        = first == std::string::npos ? std::string() : folded.substr(first, last - first + 1);
    std::string reserved = kSavedChatName;
    for (char& c : reserved) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return trimmed == reserved ? kContactNamePrefix + proposed : proposed;
}

void Session::requireSwitchedOn() const
{
    if (switchedOff_) {
        throw std::runtime_error("this account is switched off; switch it on to write");
    }
}

void Session::sendSelf(nlohmann::json inner)
{
    requireSwitchedOn();
    inner["v"] = kMessageFormatVersion;
    inner["id"] = toHex(randomBytes(16));
    inner["from"] = fingerprint();
    inner["sentAt"] = nowMillis();
    inner["device"] = client_->clientId();
    const std::string kind = inner.value("type", std::string());
    submitSignedToSelf(inner, kind);
}

void Session::syncChatPinToSelf(const std::string& peerFingerprint, bool pinned)
{
    if (myDest_.empty() || myServingKeyB64_.empty()) {
        return;
    }
    sendSelf({
        {"type", "device.chat-pin"},
        {"peer", peerFingerprint},
        {"pinned", pinned},
    });
}

void Session::syncReadToSelf(const std::string& peerFingerprint, const std::int64_t sentAtMs)
{
    if (peerFingerprint.empty() || sentAtMs <= 0) {
        return;
    }
    sendSelf({
        {"type", "device.read"},
        {"peer", peerFingerprint},
        {"ts", sentAtMs},
    });
}

void Session::syncChatClearToSelf(const std::string& peerFingerprint)
{
    sendSelf({
        {"type", "device.chat-clear"},
        {"peer", peerFingerprint},
    });
}

bool Session::isSavedChat(const std::string& peerFingerprint) const
{
    return !peerFingerprint.empty() && peerFingerprint == fingerprint();
}

bool Session::saveToSelf(nlohmann::json message)
{
    sendSelf({
        {"type", "device.saved"},
        {"message", std::move(message)},
    });
    return true;
}

void Session::clearSaved()
{
    sendSelf({{"type", "device.saved-clear"}});
}

bool Session::isBlocked(const std::string& peerFingerprint) const
{
    return blocked_.find(peerFingerprint) != blocked_.end();
}

std::vector<std::string> Session::blockedPeers() const
{
    return {blocked_.begin(), blocked_.end()};
}

void Session::persistBlocked()
{
    db_->putText("blocked", nlohmann::json(blocked_).dump());
}

void Session::setBlocked(const std::string& peerFingerprint, const bool blocked)
{
    if (peerFingerprint.empty() || isSavedChat(peerFingerprint)) {
        return;
    }
    if (blocked == isBlocked(peerFingerprint)) {
        return;
    }
    if (blocked) {
        blocked_.insert(peerFingerprint);
        revokePassFor(peerFingerprint);
    } else {
        blocked_.erase(peerFingerprint);
        if (contacts_.count(peerFingerprint) > 0) {
            registerPassFor(peerFingerprint);
        }
    }
    persistBlocked();
    try {
        sendSelf({
            {"type", "device.contact-block"},
            {"peer", peerFingerprint},
            {"blocked", blocked},
        });
    } catch (const std::exception& error) {
        bazarish::log::warn("contact-block self-sync failed: {}", error.what());
    }
}

bool Session::contactNotifications(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    return found == contacts_.end() || found->second.notifications;
}

bool Session::contactCalls(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    return found == contacts_.end() || found->second.allowCalls;
}

void Session::setContactNotifications(const std::string& peerFingerprint, const bool on)
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end() || found->second.notifications == on) {
        return;
    }
    found->second.notifications = on;
    persistContacts();
    try {
        sendSelf({
            {"type", "device.contact-prefs"},
            {"peer", peerFingerprint},
            {"notifications", on},
            {"allowCalls", found->second.allowCalls},
        });
    } catch (const std::exception& error) {
        bazarish::log::warn("contact-prefs self-sync failed: {}", error.what());
    }
}

void Session::setContactCalls(const std::string& peerFingerprint, const bool allowed)
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end() || found->second.allowCalls == allowed) {
        return;
    }
    found->second.allowCalls = allowed;
    persistContacts();
    try {
        sendSelf({
            {"type", "device.contact-prefs"},
            {"peer", peerFingerprint},
            {"notifications", found->second.notifications},
            {"allowCalls", allowed},
        });
    } catch (const std::exception& error) {
        bazarish::log::warn("contact-prefs self-sync failed: {}", error.what());
    }
}

void Session::maybeSendAvatarToContact(const std::string& peerFingerprint, const bool removal)
{
    if (avatar_.empty() && !removal) {
        return;
    }
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        return;
    }
    Contact& contact = found->second;
    if (!contact.issuedToThem || contact.avatarSentToPeer || contact.sendPass.empty()
        || contact.sealingPublicB64.empty() || contact.servingSealingB64.empty()) {
        return;
    }
    nlohmann::json inner = envelope("avatar", toHex(randomBytes(8)), {
        {"avatar", {{"mime", avatarMime_}, {"data", toBase64(avatar_)}}},
    });
    try {
        sendContent(peerFingerprint, std::move(inner));
        contact.avatarSentToPeer = true;
        persistContacts();
    } catch (const std::exception& error) {
        bazarish::log::warn(
            "avatar push to {} failed: {}", bazarish::log::redact(peerFingerprint), error.what());
    }
}

void Session::setAvatar(const Bytes& data, const std::string& mime)
{
    if (data.size() > kAvatarMaxBytes) {
        throw std::runtime_error("avatar exceeds the 500 KB protocol limit");
    }
    const bool removal = data.empty();
    std::vector<std::string> tell;
    for (const auto& [contactFp, contact] : contacts_) {
        if (!removal || contact.avatarSentToPeer) {
            tell.push_back(contactFp);
        }
    }
    storeOwnAvatar(data, mime);
    for (auto& [contactFp, contact] : contacts_) {
        (void)contactFp;
        contact.avatarSentToPeer = false;
    }
    persistContacts();
    for (const std::string& contactFp : tell) {
        maybeSendAvatarToContact(contactFp, removal);
    }
    try {
        syncAvatarToSelf();
    } catch (const std::exception& error) {
        bazarish::log::warn("avatar self-sync failed: {}", error.what());
    }
}

void Session::renameContact(const std::string& peerFingerprint, const std::string& name)
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        return;
    }
    found->second.displayName = safeContactName(name);
    persistContacts();
    try {
        syncContactNameToSelf(peerFingerprint, name);
    } catch (const std::exception& error) {
        bazarish::log::warn("contact-name self-sync failed: {}", error.what());
    }
}

void Session::removeContactEverywhere(const std::string& peerFingerprint)
{
    if (contacts_.find(peerFingerprint) == contacts_.end()) {
        return;
    }
    revokePassFor(peerFingerprint);
    try {
        sendSelf({
            {"type", "device.contact-remove"},
            {"peer", peerFingerprint},
        });
    } catch (const std::exception& error) {
        bazarish::log::warn("contact-remove self-sync failed: {}", error.what());
    }
    removeContact(peerFingerprint);
}

void Session::removeContact(const std::string& peerFingerprint)
{
    if (contacts_.erase(peerFingerprint) == 0) {
        return;
    }
    db_->erase("avatar-" + peerFingerprint);
    forgetSentFilesFor(peerFingerprint);
    persistContacts();
}

I2pDestStatus Session::i2pDestStatus()
{
    const I2pDestStatus status = client_->i2pStatus();
    approval_ = {status.approval == "pending", status.registrationMessage};
    return status;
}

StorageUsage Session::storageUsage()
{
    return client_->storageUsage();
}

std::int64_t Session::delegationDays() const
{
    return delegationDays_;
}

void Session::setDelegationDays(const std::int64_t days, const bool announce)
{
    if (days < kMinDelegationDays || days > kMaxDelegationDays) {
        throw std::invalid_argument("a delegation runs between "
            + std::to_string(kMinDelegationDays) + " and " + std::to_string(kMaxDelegationDays)
            + " days");
    }
    if (days == delegationDays_) {
        return;
    }
    delegationDays_ = days;
    persistMeta();
    if (hasI2pDestination() && !myDest_.empty()) {
        const std::int64_t expires = renewI2pTransient(static_cast<int>(delegationDays_));
        client_->sendI2pTransient(i2pTransientBase64(), expires);
    }
    if (announce) {
        syncDelegationTermToSelf();
    }
}

void Session::syncDelegationTermToSelf()
{
    const nlohmann::json inner = envelope("device.delegation-term", toHex(randomBytes(16)), {
        {"device", client_->clientId()},
        {"days", delegationDays_},
    });
    submitSignedToSelf(inner, "device.delegation-term");
}

bool Session::refreshI2pTransientIfDue(const std::int64_t now, const std::int64_t leadSeconds)
{
    if (!hasI2pDestination()) {
        return false;
    }
    const I2pDestStatus status = i2pDestStatus();
    if (!status.approved()) {
        return false;
    }
    if (status.transientExpires != 0 && status.transientExpires - now > leadSeconds) {
        return false;
    }
    const std::int64_t expiresUnix = renewI2pTransient(static_cast<int>(delegationDays_));
    client_->sendI2pTransient(i2pTransientBase64(), expiresUnix);
    return true;
}

void Session::noteWire(
    const bool outgoing, std::string what, std::string status, std::string detail) const
{
    client_->wireLog().record(
        {0, outgoing, std::move(what), std::move(status), std::move(detail)});
}

std::string Session::wireName(const std::string& peerFingerprint) const
{
    const std::string head
        = peerFingerprint.substr(0, std::min(peerFingerprint.size(), kShortFingerprintChars));
    const auto known = contacts_.find(peerFingerprint);
    if (known == contacts_.end() || known->second.displayName.empty()) {
        return head;
    }
    return known->second.displayName + " (" + head + ")";
}

std::string Session::signLogin(const std::string& challenge) const
{
    return signLoginChallenge(client_->identity(), challenge);
}

std::shared_ptr<LoginSigner> Session::loginSigner() const
{
    return std::make_shared<LoginSigner>(
        Identity::fromPrivatePem(client_->identity().privatePem()));
}

Bytes Session::passIdFor(const std::string& peerFingerprint) const
{
    return deliveryPass(deliverySecret_, peerFingerprint);
}

void Session::submitSignedToSelf(
    nlohmann::json inner, const std::string& kind, const bool later) const
{
    signAuthorship(inner, client_->identity(), /*withKeys=*/false);
    const Bytes innerBytes = encodedBody(inner);
    const Key ownSealing = Key::fromPublicDer(sealingKey_.publicDer());
    const std::string deliveryId = toHex(randomBytes(16));
    Bytes sealed = cms::seal(innerBytes, ownSealing);
    if (later && selfSendSink_) {
        selfSendSink_(deliveryId, std::move(sealed), kind);
        return;
    }
    client_->submitSelf(deliveryId, sealed, kind);
}

void Session::setSelfSendSink(SelfSendSink sink)
{
    selfSendSink_ = std::move(sink);
}

void Session::submitPrepared(
    const std::string& deliveryId, const Bytes& sealed, const std::string& kind)
{
    client_->submitSelf(deliveryId, sealed, kind);
}

IdentityKeys Session::knownKeysFor(const std::string& peerFingerprint) const
{
    if (peerFingerprint == fingerprint()) {
        return IdentityKeys{
            client_->identity().classical().publicDer(), client_->identity().pq().publicDer()};
    }
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end() || found->second.identityClassicalB64.empty()
        || found->second.identityPqB64.empty()) {
        return {};
    }
    return IdentityKeys{fromBase64(found->second.identityClassicalB64),
        fromBase64(found->second.identityPqB64)};
}

void Session::rememberKeys(Contact& contact, const IdentityKeys& keys)
{
    if (keys.empty() || !contact.identityClassicalB64.empty()) {
        return;
    }
    contact.identityClassicalB64 = toBase64(keys.classicalDer);
    contact.identityPqB64 = toBase64(keys.pqDer);
}

std::vector<WireEvent> Session::connectionLog() const
{
    return client_->wireLog().snapshot();
}

void Session::clearConnectionLog()
{
    client_->wireLog().clear();
}

std::string Session::registerPassFor(const std::string& peerFingerprint)
{
    const Bytes pass = passIdFor(peerFingerprint);
    const std::string handle = toBase64(deliveryPassHandle(pass));
    client_->registerPasses({fromBase64(handle)});
    if (pendingPassRevokes_.erase(handle) > 0) {
        persistPendingRevokes();
    }
    return toBase64(pass);
}

void Session::revokePassFor(const std::string& peerFingerprint)
{
    const std::string handle = toBase64(deliveryPassHandle(passIdFor(peerFingerprint)));
    try {
        client_->revokePasses({fromBase64(handle)});
        if (pendingPassRevokes_.erase(handle) > 0) {
            persistPendingRevokes();
        }
    } catch (const std::exception& error) {
        pendingPassRevokes_.insert(handle);
        persistPendingRevokes();
        bazarish::log::warn("a revoked delivery pass was not dropped yet: {}", error.what());
    }
}

void Session::persistPendingRevokes()
{
    db_->putText("pass-revokes", nlohmann::json(pendingPassRevokes_).dump());
}

void Session::retryPendingRevokes()
{
    if (pendingPassRevokes_.empty()) {
        return;
    }
    std::vector<Bytes> handles;
    for (const std::string& handle : pendingPassRevokes_) {
        handles.push_back(fromBase64(handle));
    }
    try {
        client_->revokePasses(handles);
        pendingPassRevokes_.clear();
        persistPendingRevokes();
    } catch (const std::exception& error) {
        bazarish::log::warn("revocations still owed to our server: {}", error.what());
    }
}

std::string Session::deliveryIdFor(
    const std::string& e2eId, const std::string& mailbox) const
{
    if (e2eId.empty()) {
        return toHex(randomBytes(kDeliveryIdBytes));
    }
    return bazarish::client::deliveryIdFor(deliveryIdSeed_, e2eId, mailbox);
}

bool Session::deliver(const std::string& toDest, const Key& servingSealingKey,
    const std::string& kind, const std::string& mailbox, const Bytes& pass,
    const Bytes& payload, const DeliveryWatch& watch, const bool waitForOutcome,
    const std::string& e2eId)
{
    const std::string deliveryId = deliveryIdFor(e2eId, mailbox);
    OutboundCourier::Task task;
    task.toDest = toDest;
    const auto known = contacts_.find(mailbox);
    task.peerName = known != contacts_.end() ? known->second.displayName : std::string();
    if (task.peerName.empty() && !mailbox.empty()) {
        task.peerName = mailbox.substr(0, std::min(mailbox.size(), kShortFingerprintChars));
    }
    task.sealed = sealDeliveryEnvelope(kind, mailbox, deliveryId, pass, servingSealingKey);
    task.payload = payload;
    task.deliveryId = deliveryId;
    task.onPhase = watch.onPhase;
    task.onOutcome = watch.onOutcome;
    OutboundCourier& courier = outboundCourier();
    if (!waitForOutcome) {
        courier.submit(std::move(task));
        return false;
    }
    const OutboundCourier::Outcome outcome = courier.deliverNow(task);
    flushPendingEchoes();
    if (!outcome.stored) {
        throw ApiError(bazarish::errorCodeFromString(outcome.errorCode), 0,
            outcome.errorMessage.empty() ? std::string("delivery failed") : outcome.errorMessage);
    }
    return true;
}

OutboundCourier& Session::outboundCourier()
{
    const std::lock_guard<std::mutex> lock(outbound_->mutex);
    if (!outbound_->courier) {
        outbound_->leases = std::make_unique<OutboundLeases>(i2pRouter(), destinationOwner());
        OutboundLeases& leases = *outbound_->leases;
        outbound_->courier = std::make_unique<OutboundCourier>(
            [&leases](const std::string& toDest, const std::string& peerName) {
                return leases.prepare(toDest, peerName);
            },
            [&leases](const std::string& toDest, const std::chrono::seconds timeout) {
                return leases.openStream(toDest, timeout);
            });
    }
    return *outbound_->courier;
}

void Session::setOutboundCourier(std::unique_ptr<OutboundCourier> courier)
{
    const std::lock_guard<std::mutex> lock(outbound_->mutex);
    outbound_->courier = std::move(courier);
}

void Session::setFetchTransport(FetchTransport transport)
{
    fetchTransportOverride_ = std::move(transport);
}

FetchTransport Session::fetchTransport() const
{
    if (fetchTransportOverride_) {
        return fetchTransportOverride_;
    }
    return [this](const std::string& toDest, const std::string& op, const Bytes& sealed) {
        return federationFetchOverI2p(routerForAdd(i2pEnabled()), toDest, op, sealed,
            transferPrivacy(), destinationOwner());
    };
}

std::string Session::addByInvite(const std::string& inviteUri, const std::string& text)
{
    const Descriptor descriptor = parseDescriptor(inviteUri);
    const ContactInfo info = client_->fetchCard(descriptor, fetchTransport());
    requestWithInfo(toHex(randomBytes(kRequestIdBytes)), descriptor.fingerprint, text, info,
        descriptor.name, descriptor.view);
    return descriptor.fingerprint;
}

Session::ContactFetchContext Session::contactFetchContext() const
{
    ContactFetchContext ctx;
    ctx.identityPem = client_->identity().privatePem();
    ctx.clientId = client_->clientId();
    ctx.endpoint = endpoint();
    ctx.i2pDataDir = i2pDirFor(accountPath_);
    ctx.resolver = resolverCoordinate_;
    ctx.i2pEnabled = i2pEnabled();
    ctx.blobFetchPrivacy = transferPrivacy();
    ctx.destinationOwner = destinationOwner();
    if (!myServingKeyB64_.empty()) {
        ctx.servingSealingKeyDer = fromBase64(myServingKeyB64_);
    }
    return ctx;
}

std::unique_ptr<Client> Session::makeEventClient(const ContactFetchContext& context)
{
    std::unique_ptr<Client> waiter = std::make_unique<Client>(
        Identity::fromPrivatePem(context.identityPem), context.clientId, context.endpoint,
        context.i2pDataDir);
    waiter->setDestinationOwner(context.destinationOwner);
    return waiter;
}

std::vector<PendingEntry> Session::waitForMail(Client& waiter, const int waitSeconds)
{
    return waiter.waitForPending(waitSeconds);
}

Session::ContactCardResolved Session::resolveContactCard(
    const ContactFetchContext& context, const ContactCardRequest& request)
{
    ContactCardResolved out;
    out.introText = request.introText;
    out.requestId = request.requestId;
    const auto started = std::chrono::steady_clock::now();
    const auto elapsedMs = [started]() -> long long {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started)
            .count();
    };
    bazarish::log::info(
        "contact-add: resolving card off-thread (byAlias={})...", request.byAlias);
    try {
        Client fetchClient(Identity::fromPrivatePem(context.identityPem), context.clientId,
            context.endpoint, context.i2pDataDir);
        const FetchTransport transport = [&context](const std::string& toDest,
                                             const std::string& op,
                                             const Bytes& sealed) -> FetchOutcome {
            return federationFetchOverI2p(routerForAdd(context.i2pEnabled), toDest, op, sealed,
                context.blobFetchPrivacy, context.destinationOwner);
        };

        const FetchTransport toRegistry = [&context](const std::string& host,
                                              const std::string& op,
                                              const Bytes& body) -> FetchOutcome {
            return resolverFetchOverI2p(routerForAdd(context.i2pEnabled), host, op, body,
                context.blobFetchPrivacy, context.destinationOwner);
        };

        if (request.byAlias) {
            const std::string alias = normalizeAlias(request.uriOrAlias);
            const Descriptor descriptor
                = fetchClient.resolveAlias(alias, context.resolver, nowSeconds(), toRegistry);
            out.info = fetchClient.fetchCard(descriptor, transport);
            out.fingerprint = descriptor.fingerprint;
            out.view = descriptor.view;
            out.displayName = safeContactName(alias);
        } else {
            const Descriptor descriptor = parseDescriptor(request.uriOrAlias);
            out.info = fetchClient.fetchCard(descriptor, transport);
            out.fingerprint = descriptor.fingerprint;
            out.view = descriptor.view;
            out.displayName = safeContactName(descriptor.name);
        }
        out.ok = true;
        bazarish::log::info("contact-add: card resolved off-thread in {} ms", elapsedMs());
    } catch (const std::exception& error) {
        out.error = error.what();
        out.ok = false;
        bazarish::log::warn(
            "contact-add: resolve failed off-thread after {} ms: {}", elapsedMs(), error.what());
    }
    return out;
}

std::string Session::commitContactAdd(const ContactCardResolved& resolved)
{
    requestWithInfo(resolved.requestId.empty() ? toHex(randomBytes(kRequestIdBytes))
                                               : resolved.requestId,
        resolved.fingerprint, resolved.introText, resolved.info, resolved.displayName,
        resolved.view);
    return resolved.fingerprint;
}

std::vector<Session::PendingContactAdd> Session::pendingContactAdds() const
{
    if (!db_->has(kPendingAddsKey)) {
        return {};
    }
    std::vector<PendingContactAdd> pending;
    const nlohmann::json stored = nlohmann::json::parse(db_->text(kPendingAddsKey));
    for (const auto& [opId, entry] : stored.items()) {
        PendingContactAdd add;
        add.opId = opId;
        add.request.byAlias = entry.value("byAlias", entry.value("byUsername", false));
        add.request.uriOrAlias = entry.value("uriOrAlias", std::string());
        add.request.introText = entry.value("intro", std::string());
        add.request.requestId = entry.value("requestId", std::string());
        pending.push_back(std::move(add));
    }
    return pending;
}

void Session::notePendingContactAdd(const PendingContactAdd& pending)
{
    nlohmann::json stored = db_->has(kPendingAddsKey)
        ? nlohmann::json::parse(db_->text(kPendingAddsKey))
        : nlohmann::json::object();
    stored[pending.opId] = {{"byAlias", pending.request.byAlias},
        {"uriOrAlias", pending.request.uriOrAlias}, {"intro", pending.request.introText},
        {"requestId", pending.request.requestId}};
    db_->putText(kPendingAddsKey, stored.dump());
}

void Session::forgetPendingContactAdd(const std::string& opId)
{
    if (!db_->has(kPendingAddsKey)) {
        return;
    }
    nlohmann::json stored = nlohmann::json::parse(db_->text(kPendingAddsKey));
    stored.erase(opId);
    db_->putText(kPendingAddsKey, stored.dump());
}

void Session::setResolverCoordinate(ResolverCoordinate coordinate)
{
    resolverCoordinate_ = std::move(coordinate);
}

std::string Session::addByAlias(const std::string& alias, const std::string& text)
{
    if (!resolverCoordinate_.configured()) {
        throw std::runtime_error("no alias resolver is configured in this build");
    }
    const std::string normalized = normalizeAlias(alias);
    const Descriptor descriptor
        = client_->resolveAlias(normalized, resolverCoordinate_, nowSeconds(), heldTransport());
    const ContactInfo info = client_->fetchCard(descriptor, fetchTransport());
    requestWithInfo(toHex(randomBytes(kRequestIdBytes)), descriptor.fingerprint, text, info,
        alias, descriptor.view);
    return descriptor.fingerprint;
}

void Session::requestWithInfo(const std::string& requestId, const std::string& peerFingerprint,
    const std::string& text, const ContactInfo& info, const std::string& displayName,
    const std::string& descriptorView)
{
    if (info.card.fingerprint() != peerFingerprint) {
        throw std::runtime_error("contact lookup returned a different user");
    }
    if (contacts_.find(peerFingerprint) != contacts_.end()) {
        throw std::runtime_error("they are already in your contacts");
    }
    if (text.size() > kMaxContactGreetingBytes) {
        throw std::runtime_error("the introduction may be at most "
            + std::to_string(kMaxContactGreetingBytes) + " characters");
    }
    const Key peerPrekey = info.card.sealingKey();
    const Key peerServingKey = info.card.servingSealingKey();
    const std::string peerDest = info.card.dest;
    validateB32I2pHost(peerDest);

    const std::string replyPass = registerPassFor(peerFingerprint);

    const nlohmann::json payload = envelope("contact.request", requestId, {
        {"text", text},
        {"dn", name_},
        {"bootstrap",
            {
                {"sealing", sealingPublicB64()},
                {"dest", myDest_},
                {"servingKey", myServingKeyB64_},
                {"view", sharedView()},
                {"pass", replyPass},
            }},
    });
    nlohmann::json request = payload;
    signAuthorship(request, client_->identity(), /*withKeys=*/true);
    const Bytes encrypted = cms::seal(encodedBody(request), peerPrekey);
    deliver(peerDest, peerServingKey, "contact", peerFingerprint, {}, encrypted,
        DeliveryWatch{}, /*waitForOutcome=*/true, requestId);

    Contact& contact = contacts_[peerFingerprint];
    contact.dest = peerDest;
    contact.sealingPublicB64 = toBase64(peerPrekey.publicDer());
    contact.servingSealingB64 = toBase64(peerServingKey.publicDer());
    rememberKeys(contact, IdentityKeys{info.card.identityClassicalDer, info.card.identityPqDer});
    contact.issuedToThem = true;
    contact.view = descriptorView;
    if (!displayName.empty()) {
        contact.displayName = safeContactName(displayName);
    }
    persistContacts();
}

void Session::acceptContactRequest(const std::string& peerFingerprint)
{
    const auto existing = contacts_.find(peerFingerprint);
    if (existing != contacts_.end()
        && (existing->second.issuedToThem || existing->second.acceptInFlight)) {
        bazarish::log::info("contact request from {} was already agreed to",
            bazarish::log::redact(peerFingerprint));
        return;
    }
    nlohmann::json inner = envelope("contact.accept", toHex(randomBytes(8)), {
        {"dn", name_},
    });
    sendContent(peerFingerprint, std::move(inner));
}

bool Session::sendMessage(const std::string& peerFingerprint, const std::string& text,
    const std::string& e2eId, const DeliveryWatch& watch, const std::string& replyTo,
    const bool forwarded)
{
    nlohmann::json inner = envelope("text", e2eId.empty() ? toHex(randomBytes(8)) : e2eId, {
        {"text", text},
    });
    addReplyAndForward(inner, replyTo, forwarded);
    return sendContent(peerFingerprint, std::move(inner), watch);
}

bool Session::sendFile(const std::string& peerFingerprint, const fs::path& path,
    const std::string& e2eId, const DeliveryWatch& watch, const std::string& replyTo)
{
    if (isSavedChat(peerFingerprint)) {
        throw std::runtime_error("a file cannot be kept in Saved messages: its bytes travel"
            " between the two devices in a conversation, so there would be nothing to open"
            " on another device");
    }
    return announceTransfer(
        kTypeFile, peerFingerprint, path, e2eId, watch, replyTo);
}

bool Session::sendPicture(const std::string& peerFingerprint, const fs::path& path,
    const std::string& e2eId, const DeliveryWatch& watch, const std::string& replyTo)
{
    // A picture rides inside the message.
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot read the picture: " + path.string());
    }
    const Bytes bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (bytes.empty()) {
        throw std::runtime_error("the picture is empty: " + path.string());
    }

    const std::string id = e2eId.empty() ? toHex(randomBytes(8)) : e2eId;
    putPicture(id, bytes);

    nlohmann::json inner = envelope(kTypeImage, id, {
        {"image",
            {
                {"name", path.filename().string()},
                {"mime", guessMime(path)},
                {"size", bytes.size()},
                {"data", nlohmann::json::binary(bytes)},
            }},
    });
    addReplyAndForward(inner, replyTo, /*forwarded=*/false);
    return sendContent(peerFingerprint, std::move(inner), watch);
}

bool Session::sendVoice(const std::string& peerFingerprint, const Bytes& opus,
    const std::int64_t durationMs, const std::string& e2eId,
    const DeliveryWatch& watch, const std::string& replyTo, const bool forwarded)
{
    if (opus.empty()) {
        throw std::runtime_error("there is nothing recorded to send");
    }
    const std::string id = e2eId.empty() ? toHex(randomBytes(8)) : e2eId;
    putVoice(id, opus);

    nlohmann::json inner = envelope(kTypeVoice, id, {
        {"voice",
            {
                        {"durationMs", durationMs},
                {"size", opus.size()},
                {"data", nlohmann::json::binary(opus)},
            }},
    });
    addReplyAndForward(inner, replyTo, forwarded);
    return sendContent(peerFingerprint, std::move(inner), watch);
}

bool Session::announceTransfer(const std::string& type, const std::string& peerFingerprint,
    const fs::path& path, const std::string& e2eId,
    const DeliveryWatch& watch, const std::string& replyTo)
{
    const std::string id = e2eId.empty() ? toHex(randomBytes(8)) : e2eId;
    const std::uint64_t size = fs::file_size(path);
    const std::string digest = toHex(sha256File(path));
    sentFiles_[id] = SentFile{path, digest, size, peerFingerprint};
    persistSentFiles();

    nlohmann::json inner = envelope(type, id, {
        {"file",
            {
                {"name", path.filename().string()},
                {"size", size},
                {"sha256", digest},
                {"mime", guessMime(path)},
            }},
    });
    addReplyAndForward(inner, replyTo, /*forwarded=*/false);
    return sendContent(peerFingerprint, std::move(inner), watch);
}

void Session::sendInteractive(const std::string& peerFingerprint, const std::string& text,
    const InlineKeyboard& keyboard, const std::string& e2eId,
    const DeliveryWatch& watch)
{
    nlohmann::json inner = envelope("text", e2eId.empty() ? toHex(randomBytes(8)) : e2eId, {
        {"text", text},
        {"keyboard", keyboardToJson(keyboard)},
    });
    sendContent(peerFingerprint, std::move(inner), watch);
}

void Session::sendCommand(const std::string& peerFingerprint, const std::string& command,
    const std::string& args, const std::string& e2eId,
    const DeliveryWatch& watch)
{
    nlohmann::json inner = envelope("bot.command", e2eId.empty() ? toHex(randomBytes(8)) : e2eId, {
        {"command", command},
        {"args", args},
    });
    sendContent(peerFingerprint, std::move(inner), watch);
}

void Session::sendCallback(
    const std::string& peerFingerprint, const std::string& data, const std::string& refMessageId)
{
    nlohmann::json inner = envelope("bot.callback", toHex(randomBytes(8)), {
        {"data", data},
        {"ref", refMessageId},
    });
    sendContent(peerFingerprint, std::move(inner));
}

bool Session::sendEdit(const std::string& peerFingerprint, const std::string& refMessageId,
    const std::string& text, const InlineKeyboard& keyboard,
    const DeliveryWatch& watch)
{
    nlohmann::json inner = envelope("edit", toHex(randomBytes(8)), {
        {"ref", refMessageId},
        {"text", text},
        {"keyboard", keyboardToJson(keyboard)},
    });
    return sendContent(peerFingerprint, std::move(inner), watch);
}

void Session::sendDelete(const std::string& peerFingerprint, const std::string& refMessageId)
{
    nlohmann::json inner = envelope("delete", toHex(randomBytes(8)), {
        {"ref", refMessageId},
    });
    sendContent(peerFingerprint, std::move(inner));
}

void Session::setSharingAllowed(const bool allowed)
{
    if (sharingAllowed_ == allowed) {
        return;
    }
    sharingAllowed_ = allowed;
    persistMeta();
}

void Session::rotateServingKey(const std::function<void(const std::string&)>& onStage)
{
    const auto stage = [&onStage](const std::string& text) {
        if (onStage) {
            onStage(text);
        }
    };
    if (myDest_.empty()) {
        throw std::runtime_error("no destination of your own yet - connect first");
    }
    stage("Asking your server for a new serving key");
    const Client::PreparedServingKey prepared = client_->prepareServingKey();
    stage("Signing a card over the new key");
    const Bytes card = ContactCard::issue(client_->identity(), nowSeconds(), myDest_,
        sealingKey_.publicDer(), prepared.servingSealingKeyDer);
    stage("Putting the new key in force");
    client_->commitServingKey(card);
    cardB64_ = toBase64(card);
    myServingKeyB64_ = toBase64(prepared.servingSealingKeyDer);
    view_ = prepared.view;
    persistMeta();
    stage("Telling the name service");
    serviceAliasesAfterMove();
    stage("Telling your contacts");
    const RoutingPushResult pushed = pushRoutingToContacts(onStage);
    stage(pushed.failed == 0
            ? ("Done - " + std::to_string(pushed.told) + " contact(s) told")
            : ("Done - " + std::to_string(pushed.told) + " told, " + std::to_string(pushed.failed)
                + " could not be reached; they get it with your next message"));
}

Session::RoutingPushResult Session::pushRoutingToContacts(
    const std::function<void(const std::string&)>& onStage)
{
    RoutingPushResult result;
    std::vector<std::string> peers;
    for (const auto& [fingerprint, contact] : contacts_) {
        if (contact.issuedToThem && !contact.sealingPublicB64.empty()
            && !contact.servingSealingB64.empty()) {
            peers.push_back(fingerprint);
        }
    }
    for (const std::string& peer : peers) {
        if (onStage) {
            onStage("Telling your contacts (" + std::to_string(result.told + result.failed + 1)
                + "/" + std::to_string(peers.size()) + ")");
        }
        nlohmann::json inner = envelope("contact.routing", toHex(randomBytes(8)));
        try {
            sendContent(peer, std::move(inner), {}, false,
                /*establishOnFirstReply=*/false);
            ++result.told;
        } catch (const std::exception& error) {
            ++result.failed;
            bazarish::log::warn("routing update not delivered to {}: {}",
                bazarish::log::redact(peer), error.what());
        }
    }
    return result;
}

void Session::sendReceipt(const std::string& peerFingerprint, const std::string& refMessageId)
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end() || found->second.sendPass.empty()) {
        return;
    }
    if (!found->second.issuedToThem) {
        return;
    }
    nlohmann::json inner = envelope("receipt", toHex(randomBytes(8)), {
        {"ref", refMessageId},
    });
    bazarish::log::info("read receipt for {} on its way to {}", refMessageId,
        bazarish::log::redact(peerFingerprint));
    if (!sendContent(peerFingerprint, std::move(inner), {}, false,
            /*establishOnFirstReply=*/false)) {
        bazarish::log::info("the read receipt for {} waits for a token", refMessageId);
    }
}

void Session::sendReaction(const std::string& peerFingerprint, const std::string& refMessageId,
    const std::string& emoji)
{
    if (!reactionWithinLimits(emoji)) {
        throw std::runtime_error("a reaction is at most "
            + std::to_string(kMaxReactionChars) + " characters");
    }
    nlohmann::json inner = envelope("reaction", toHex(randomBytes(8)), {
        {"ref", refMessageId},
        {"text", emoji},
    });
    sendContent(peerFingerprint, std::move(inner));
}

void Session::sendChatClear(const std::string& peerFingerprint)
{
    nlohmann::json inner = envelope("chat.clear", toHex(randomBytes(8)));
    sendContent(peerFingerprint, std::move(inner));
}

void Session::setTransferHandler(TransferEventFn handler)
{
    const std::lock_guard<std::mutex> lock(transfers_->mutex);
    transfers_->onEvent = std::move(handler);
}

void Session::emitTransfer(const std::string& e2eId, const TransferState state,
    const std::uint64_t bytes, const std::uint64_t total, const std::string& error,
    const std::string& stage, const std::string& peer)
{
    TransferEventFn handler;
    {
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        handler = transfers_->onEvent;
    }
    if (handler) {
        handler(TransferEvent{e2eId, peer, state, bytes, total, error, stage});
    }
}

void Session::requestFile(
    const std::string& peerFingerprint, const std::string& e2eId, const fs::path& dest)
{

    const std::string ask = toHex(randomBytes(kTransferAskBytes));
    {
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        transfers_->pending[e2eId] = PendingTransfer{
            dest, std::make_shared<std::atomic<bool>>(false), peerFingerprint, ask};
    }
    emitTransfer(e2eId, TransferState::eRequested, 0, 0, {}, "Asking the sender",
        peerFingerprint);
    nlohmann::json inner = envelope("file.request", toHex(randomBytes(8)), {
        {"fileId", e2eId},
        {"ask", ask},
    });
    sendContent(peerFingerprint, std::move(inner));
}

void Session::dropServe(
    const std::string& serveId, const std::shared_ptr<std::atomic<bool>>& cancel)
{
    const std::lock_guard<std::mutex> lock(transfers_->mutex);
    const auto found = transfers_->serving.find(serveId);
    if (found != transfers_->serving.end() && found->second.cancel == cancel) {
        transfers_->serving.erase(found);
    }
}

bool Session::awaitingAsk(const std::string& ask) const
{
    const std::lock_guard<std::mutex> lock(transfers_->mutex);
    for (const auto& [fileId, pending] : transfers_->pending) {
        if (pending.ask == ask) {
            return true;
        }
    }
    return false;
}

std::vector<Session::StoppedHalf> Session::stopTransfer(
    const std::string& fileId, const std::string& fromPeer, const std::string& forAsk)
{
    std::vector<StoppedHalf> stopped;
    {
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        const auto found = transfers_->pending.find(fileId);
        if (found != transfers_->pending.end()
            && (fromPeer.empty() || found->second.peer == fromPeer)
            && (forAsk.empty() || forAsk == found->second.ask)) {
            found->second.cancel->store(true);
            stopped.push_back(StoppedHalf{found->second.peer, found->second.ask});
            transfers_->pending.erase(found);
        }
        for (auto it = transfers_->serving.begin(); it != transfers_->serving.end();) {
            const ServingTransfer& serve = it->second;
            const bool stops = serve.fileId == fileId
                && (fromPeer.empty() || serve.peer == fromPeer)
                && (forAsk.empty() || serve.forAsk == forAsk);
            if (!stops) {
                ++it;
                continue;
            }
            serve.cancel->store(true);
            stopped.push_back(StoppedHalf{serve.peer, serve.forAsk});
            it = transfers_->serving.erase(it);
        }
    }
    for (const StoppedHalf& half : stopped) {
        emitTransfer(fileId, TransferState::eFailed, 0, 0,
            fromPeer.empty() ? "you stopped this transfer" : "the transfer was stopped", {},
            half.peer);
    }
    return stopped;
}

void Session::cancelTransfer(const std::string& e2eId)
{
    for (const StoppedHalf& half : stopTransfer(e2eId)) {
        try {
            sendContent(half.peer,
                envelope("file.cancel", toHex(randomBytes(8)),
                    {{"fileId", e2eId}, {"ask", half.ask}}));
        } catch (const std::exception& error) {
            bazarish::log::warn("could not tell {} the transfer was stopped: {}",
                bazarish::log::redact(half.peer), error.what());
        }
    }
}

void Session::forgetSentFilesFor(const std::string& peerFingerprint)
{
    bool dropped = false;
    for (auto it = sentFiles_.begin(); it != sentFiles_.end();) {
        if (it->second.peer == peerFingerprint) {
            it = sentFiles_.erase(it);
            dropped = true;
        } else {
            ++it;
        }
    }
    if (dropped) {
        persistSentFiles();
    }
}

void Session::unsend(const std::string& e2eId)
{
    if (sentFiles_.erase(e2eId) > 0) {
        persistSentFiles();
    }
}

void Session::releaseI2pLinks()
{
    client_->releaseI2pLink();
}

bazarish::i2p::Privacy Session::transferPrivacy() const
{
    return transferPrivacy_.value_or(tunnelPrivacy());
}

void Session::setTransferPrivacy(const bazarish::i2p::Privacy privacy)
{
    transferPrivacy_ = privacy;
}

void Session::serveRequestedFile(const std::string& peerFingerprint, const std::string& fileId,
    const std::string& forAsk)
{
    const auto found = sentFiles_.find(fileId);
    if (found == sentFiles_.end()) {
        return;
    }
    if (!found->second.peer.empty() && found->second.peer != peerFingerprint) {
        bazarish::log::warn("file request for another contact's file from {}, ignored",
            bazarish::log::redact(peerFingerprint));
        return;
    }
    if (!fs::exists(found->second.path)) {
        nlohmann::json inner = envelope("file.unavailable", toHex(randomBytes(8)), {
            {"fileId", fileId},
        });
        sendContent(peerFingerprint, std::move(inner));
        return;
    }
    const fs::path source = found->second.path;
    const fs::path scratch = accountPath_.parent_path() / ".transfers";
    fs::create_directories(scratch);
    const fs::path ciphertextPath = scratch / ("file-serve-" + toHex(randomBytes(8)) + ".tmp");

    const std::string serveId = forAsk.empty() ? fileId : fileId + "@" + forAsk;
    const std::shared_ptr<std::atomic<bool>> cancel = std::make_shared<std::atomic<bool>>(false);
    {
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        transfers_->serving[serveId]
            = ServingTransfer{cancel, fileId, peerFingerprint, forAsk};
    }
    std::thread([this, peerFingerprint, fileId, serveId, forAsk, source, ciphertextPath,
                    cancel]() {
        try {
            emitTransfer(
                fileId, TransferState::eRequested, 0, 0, {}, "Encrypting", peerFingerprint);
            const PreparedFile prepared = prepareFile(source, ciphertextPath);
            emitTransfer(fileId, TransferState::eRequested, 0, 0, {}, "Making an address",
                peerFingerprint);
            bazarish::i2p::EndpointConfig config;
            config.privacy = transferPrivacy();
            config.tunnelQuantity = 2;
            config.label = "File upload";
            config.bulk = true;
            config.owner = destinationOwner();
            const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
                = i2pRouter().createEndpoint(config);
            emitTransfer(fileId, TransferState::eRequested, 0, 0, {}, "Publishing the address",
                peerFingerprint);
            const auto publishDeadline
                = std::chrono::steady_clock::now() + std::chrono::seconds(kPublishWaitSeconds);
            while (!endpoint->waitReady(std::chrono::seconds(kPublishPollSeconds))) {
                if (cancel->load()) {
                    throw std::runtime_error("transfer stopped");
                }
                if (std::chrono::steady_clock::now() >= publishDeadline) {
                    throw std::runtime_error("could not publish a one-time destination");
                }
            }

            FileOffer offer;
            offer.fileId = fileId;
            offer.host = endpoint->routingHost();
            offer.key = prepared.key;
            offer.sha256 = prepared.sha256;
            offer.size = prepared.size;
            nlohmann::json inner = envelope("file.offer", toHex(randomBytes(8)), {
                {"offer", fileOfferToJson(offer)},
                {"forAsk", forAsk},
            });
            sendContent(peerFingerprint, std::move(inner));
            emitTransfer(fileId, TransferState::eRequested, 0, 0, {}, "Waiting for them",
                peerFingerprint);

            const bool served
                = serveFile(*endpoint, ciphertextPath, std::chrono::seconds(kServeWindowSeconds),
                    [this, fileId, peerFingerprint](const std::uint64_t sent,
                        const std::uint64_t total) {
                        emitTransfer(fileId, TransferState::eRunning, sent, total, {}, "Sending",
                            peerFingerprint);
                    },
                    cancel.get());
            if (!served) {
                throw std::runtime_error(
                    cancel->load() ? "transfer stopped" : "your contact never connected");
            }
            emitTransfer(fileId, TransferState::eDone, 0, 0, {}, {}, peerFingerprint);
            dropServe(serveId, cancel);
        } catch (const std::exception& error) {
            if (cancel->load()) {
                std::error_code stoppedEc;
                fs::remove(ciphertextPath, stoppedEc);
                return;
            }
            emitTransfer(
                fileId, TransferState::eFailed, 0, 0, error.what(), {}, peerFingerprint);
            dropServe(serveId, cancel);
            try {
                sendContent(peerFingerprint,
                    envelope("file.unavailable", toHex(randomBytes(8)),
                        {{"fileId", fileId}}));
            } catch (const std::exception& tellError) {
                bazarish::log::warn("could not tell {} the transfer failed: {}",
                    bazarish::log::redact(peerFingerprint), tellError.what());
            }
        }
        std::error_code ec;
        fs::remove(ciphertextPath, ec);
    }).detach();
}

void Session::startAnnouncedFetch(const FileOffer& offer, const std::string& peer)
{
    fs::path dest;
    std::shared_ptr<std::atomic<bool>> cancel;
    {
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        const auto found = transfers_->pending.find(offer.fileId);
        if (found == transfers_->pending.end()) {
            return;
        }
        if (found->second.fetching) {
            bazarish::log::info("a second offer for a file already being fetched: ignored");
            return;
        }
        found->second.fetching = true;
        dest = found->second.dest;
        cancel = found->second.cancel;
    }

    std::thread([this, offer, dest, cancel, peer]() {
        try {
            emitTransfer(offer.fileId, TransferState::eRequested, 0, 0, {}, "Connecting", peer);
            fetchFileOverI2p(i2pRouter(), offer, dest, transferPrivacy(),
                [this, &offer, &peer](const std::uint64_t got, const std::uint64_t total) {
                    emitTransfer(
                        offer.fileId, TransferState::eRunning, got, total, {}, "Receiving", peer);
                },
                cancel.get(), destinationOwner());
            emitTransfer(offer.fileId, TransferState::eDone, offer.size, offer.size, {}, {}, peer);
        } catch (const std::exception& error) {
            if (!cancel->load()) {
                emitTransfer(offer.fileId, TransferState::eFailed, 0, 0, error.what(), {}, peer);
            }
        }
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        const auto found = transfers_->pending.find(offer.fileId);
        if (found != transfers_->pending.end() && found->second.cancel == cancel) {
            transfers_->pending.erase(found);
        }
    }).detach();
}

nlohmann::json Session::envelope(
    const std::string& type, const std::string& id, nlohmann::json payload) const
{
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", type},
        {"id", id},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
    };
    inner.update(std::move(payload));
    return inner;
}

bool Session::sendContent(const std::string& peerFingerprint, nlohmann::json inner,
    const DeliveryWatch& watch, bool waitForOutcome, bool establishOnFirstReply)
{
    requireSwitchedOn();
    if (isSavedChat(peerFingerprint)) {
        const bool kept = saveToSelf(std::move(inner));
        if (watch.onOutcome) {
            OutboundCourier::Outcome outcome;
            outcome.stored = kept;
            watch.onOutcome(outcome);
        }
        return kept;
    }
    if (isBlocked(peerFingerprint)) {
        throw std::runtime_error("this contact is blocked; unblock them to write to them");
    }
    const nlohmann::json echoPayload
        = echoesToOwnDevices(inner.value("type", std::string())) ? inner : nlohmann::json();
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        throw std::runtime_error("unknown contact: " + peerFingerprint);
    }
    Contact& contact = found->second;
    if (contact.sealingPublicB64.empty() || contact.servingSealingB64.empty()) {
        throw std::runtime_error("contact not established yet: " + peerFingerprint);
    }
    if (const Bytes body = encodedBody(inner); body.size() > kMaxMessagePayloadBytes) {
        throw std::runtime_error("this message is too large to send ("
            + std::to_string(body.size() / 1024) + " KiB; the limit is "
            + std::to_string(kMaxMessagePayloadBytes / 1024) + " KiB) - send it as a file");
    }
    if (contact.sendPass.empty()) {
        throw std::runtime_error("no delivery pass for this contact yet: " + peerFingerprint);
    }
    bool bootstrapIssued = false;
    DeliveryWatch watchWithLog = watch;

    if (establishOnFirstReply && !contact.issuedToThem && !contact.acceptInFlight) {
        inner["bootstrap"] = {
            {"sealing", sealingPublicB64()},
            {"dest", myDest_},
            {"servingKey", myServingKeyB64_},
            {"view", sharedView()},
            {"pass", registerPassFor(peerFingerprint)},
        };
        bootstrapIssued = true;
    }

    inner["routing"]
        = {{"dest", myDest_}, {"servingKey", myServingKeyB64_}, {"view", sharedView()}};

    signAuthorship(inner, client_->identity(), /*withKeys=*/false);
    const Bytes innerBytes = encodedBody(inner);
    const Key peerSealing = Key::fromPublicDer(fromBase64(contact.sealingPublicB64));
    const Bytes payload = cms::seal(innerBytes, peerSealing);
    const Key peerServingKey = Key::fromPublicDer(fromBase64(contact.servingSealingB64));
    const Bytes pass = fromBase64(contact.sendPass);

    if (bootstrapIssued) {
        contact.acceptInFlight = true;
    }
    {
        const std::string kind = inner.value("type", std::string("?"));
        const std::string peerLabel = wireName(peerFingerprint);
        const std::string shortId
            = deliveryIdFor(inner.value("id", std::string()), peerFingerprint)
                  .substr(0, kShortFingerprintChars);
        noteWire(true, kind + " to " + peerLabel, "sending",
            "id " + shortId + ", pass " + toHex(pass).substr(0, kPassPrefixChars));
        DeliveryWatch logged = watch;
        const std::shared_ptr<WireLog> log = client_->wireLogHandle();
        logged.onOutcome = [log, kind, peerLabel, shortId, peerFingerprint, echoPayload,
                               echoQueue = echoQueue_, onOutcome = watch.onOutcome,
                               bootstrapIssued](const OutboundCourier::Outcome& outcome) {
            const std::string status = outcome.stored
                ? std::string("stored")
                : "failed" + (outcome.errorCode.empty() ? std::string() : ": " + outcome.errorCode);
            log->record({0, true, kind + " to " + peerLabel, status, "id " + shortId});
            if (outcome.stored && !echoPayload.is_null()) {
                const std::lock_guard<std::mutex> lock(echoQueue->mutex);
                echoQueue->pending.push_back({peerFingerprint, echoPayload});
            }
            if (bootstrapIssued) {
                const std::lock_guard<std::mutex> lock(echoQueue->mutex);
                if (outcome.stored) {
                    echoQueue->established.push_back(peerFingerprint);
                } else {
                    echoQueue->notEstablished.push_back(peerFingerprint);
                }
            }
            if (onOutcome) {
                onOutcome(outcome);
            }
        };
        watchWithLog = std::move(logged);
    }

    const bool delivered = deliver(contact.dest, peerServingKey, "content", peerFingerprint,
        pass, payload, watchWithLog, waitForOutcome, inner.value("id", std::string()));
    return delivered;
}

void Session::loadSentFiles()
{
    if (!db_->has("sent-files")) {
        return;
    }
    const nlohmann::json stored = nlohmann::json::parse(db_->text("sent-files"));
    for (const auto& [id, entry] : stored.items()) {
        sentFiles_[id] = SentFile{fs::path(entry.at("path").get<std::string>()),
            entry.value("sha256", std::string()), entry.value("size", std::uint64_t{0}),
            entry.value("peer", std::string())};
    }
}

void Session::persistSentFiles() const
{
    nlohmann::json stored = nlohmann::json::object();
    for (const auto& [id, file] : sentFiles_) {
        stored[id] = {
            {"path", file.path.string()},
            {"sha256", file.sha256},
            {"size", file.size},
            {"peer", file.peer},
        };
    }
    db_->putText("sent-files", stored.dump());
}

std::vector<IncomingMessage> Session::sync(bool autoAckSurfaced, const std::size_t maxItems)
{
    flushPendingEchoes();
    std::vector<IncomingMessage> result;
    std::set<std::string> establishedPeers;
    std::set<std::string> reaskedPeers;
    std::vector<PendingEntry> waiting;
    {
        const log::Slow timed("asking what the mailbox holds", kSlowStretch);
        waiting = client_->listPending();
    }
    if (serverAnswered_) {
        serverAnswered_();
    }
    const log::Slow timedItems(
        "taking in the " + std::to_string(waiting.size()) + " item(s) the mailbox held",
        kSlowStretch);
    morePending_ = false;
    std::size_t handled = 0;
    for (const PendingEntry& entry : waiting) {
        if (awaitingAck_.find(entry.id) != awaitingAck_.end()) {
            continue;
        }
        if (maxItems > 0 && handled >= maxItems) {
            morePending_ = true;
            break;
        }
        ++handled;
        const log::Slow timedItem("taking in " + entry.id, kSlowStretch);
        try {
            Bytes blob;
            if (const auto held = fetched_.find(entry.id); held != fetched_.end()) {
                blob = std::move(held->second);
                fetched_.erase(held);
            } else {
                blob = client_->fetchBlob(entry.id);
            }
            const Bytes plain = cms::unseal(blob, sealingKey_);
            nlohmann::json body = decodedBody(plain);

            {
                const std::string claimed = body.value("from", std::string());
                std::string author;
                try {
                    author = authorOf(body, knownKeysFor(claimed));
                } catch (const std::exception& error) {
                    bazarish::log::warn("sync: dropping an item that does not name its "
                                        "author: {}", error.what());
                    noteWire(false, "unsigned item", "dropped", error.what());
                    releaseItem(entry.id);
                    continue;
                }
                if (author != claimed) {
                    bazarish::log::warn("sync: dropping an item signed by {} claiming to be {}",
                        bazarish::log::redact(author), bazarish::log::redact(claimed));
                    noteWire(false, "item signed by another key", "dropped", {});
                    releaseItem(entry.id);
                    continue;
                }
            }

            if (body.value("v", kMessageFormatVersion) > kMessageFormatVersion) {
                bazarish::log::info("sync: an item from a newer message format was not read");
                noteWire(false, "item in a newer format", "dropped", {});
                releaseItem(entry.id);
                continue;
            }

            IncomingMessage message;
            message.deliveryClass = entry.deliveryClass;
            if (body.value("type", std::string()) == "device.message"
                && body.value("from", std::string()) == fingerprint()) {
                if (body.value("device", std::string()) == client_->clientId()) {
                    releaseItem(entry.id);
                    continue;
                }
                const std::string peer = body.value("peer", std::string());
                body = body.at("message");
                body["from"] = peer;
                message.sentByUs = true;
            }
            if (body.value("type", std::string()) == "device.saved"
                && body.value("from", std::string()) == fingerprint()) {
                if (body.value("device", std::string()) == client_->clientId()) {
                    releaseItem(entry.id);
                    continue;
                }
                body = body.at("message");
                body["from"] = fingerprint();
                message.sentByUs = true;
            }
            message.fromFingerprint = body.at("from").get<std::string>();
            message.e2eId = body.value("id", std::string());
            message.sentAt = body.value("sentAt", static_cast<std::int64_t>(0));
            message.forwarded = body.value("forwarded", false);
            std::string type = body.value("type", std::string("text"));

            const bool fromOurselves = message.fromFingerprint == fingerprint();
            const bool known = contacts_.find(message.fromFingerprint) != contacts_.end();
            const bool asking = type == "contact.request";
            if (!fromOurselves
                && (isBlocked(message.fromFingerprint) || (!known && !asking))) {
                releaseItem(entry.id);
                continue;
            }

            if (body.contains("routing")) {
                const nlohmann::json& routing = body.at("routing");
                Contact& peer = contacts_[message.fromFingerprint];
                const std::string dest = routing.value("dest", std::string());
                const std::string servingKey = routing.value("servingKey", std::string());
                if (!dest.empty() && !servingKey.empty()
                    && (peer.dest != dest || peer.servingSealingB64 != servingKey)) {
                    validateB32I2pHost(dest);
                    bazarish::log::info("contact {} answers at a new destination now",
                        bazarish::log::redact(message.fromFingerprint));
                    peer.dest = dest;
                    peer.servingSealingB64 = servingKey;
                    persistContacts();
                }
                if (routing.contains("view")) {
                    const std::string view = routing.value("view", std::string());
                    const bool refused = view.empty();
                    if (isViewCapability(view) && (peer.view != view || peer.sharingRefused)) {
                        peer.view = view;
                        peer.sharingRefused = false;
                        persistContacts();
                    } else if (refused && (!peer.view.empty() || !peer.sharingRefused)) {
                        peer.view.clear();
                        peer.sharingRefused = true;
                        persistContacts();
                    }
                }
            }

            if (body.contains("bootstrap")) {
                Contact& peer = contacts_[message.fromFingerprint];
                rememberKeys(peer, keysIn(body));
                applyBootstrap(peer, body.at("bootstrap"));
                message.establishedContact = true;
                establishedPeers.insert(message.fromFingerprint);
            }

            if (type == "contact.request" || type == "contact.accept") {
                const std::string dn = body.value("dn", std::string());
                Contact& peer = contacts_[message.fromFingerprint];
                if (!dn.empty() && peer.displayName.empty()) {
                    peer.displayName = safeContactName(dn);
                }
            }

            if (asking && known && contacts_[message.fromFingerprint].issuedToThem) {
                contacts_[message.fromFingerprint].issuedToThem = false;
                reaskedPeers.insert(message.fromFingerprint);
            }

            if (type == "text" || type == "contact.request") {
                message.contentType = type;
                message.text = body.value("text", std::string());
            } else if (type == kTypeImage) {
                message.contentType = type;
                const nlohmann::json& picture = body.at("image");
                message.attachmentName = picture.value("name", std::string());
                message.attachmentMime = picture.value("mime", std::string());
                message.attachmentSize = picture.value("size", std::uint64_t{0});
                const nlohmann::json::binary_t& data = picture.at("data").get_binary();
                putPicture(message.e2eId, Bytes(data.begin(), data.end()));
            } else if (type == kTypeVoice) {
                message.contentType = type;
                const nlohmann::json& voice = body.at("voice");
                message.attachmentMime = "audio/opus";
                message.attachmentSize = voice.value("size", std::uint64_t{0});
                message.attachmentDurationMs = voice.value("durationMs", std::int64_t{0});
                const nlohmann::json::binary_t& data = voice.at("data").get_binary();
                putVoice(message.e2eId, Bytes(data.begin(), data.end()));
            } else if (type == kTypeFile || type == "audio") {
                message.contentType = type;
                const nlohmann::json& file = body.at("file");
                message.attachmentRef = file.value("sha256", std::string());
                message.attachmentName = file.value("name", std::string());
                message.attachmentMime = file.value("mime", std::string());
                message.attachmentSize = file.value("size", std::uint64_t{0});
            } else if (type == "file.request") {
                message.contentType = type;
                const std::int64_t askedAt = body.value("sentAt", std::int64_t{0});
                if (askedAt != 0 && nowMillis() - askedAt > kFileRequestFreshnessMs) {
                    bazarish::log::info("file request from {} is stale, not serving",
                        bazarish::log::redact(message.fromFingerprint));
                } else {
                    serveRequestedFile(message.fromFingerprint,
                        body.value("fileId", std::string()), body.value("ask", std::string()));
                }
            } else if (type == "file.offer") {
                message.contentType = type;
                const std::string offerFor = body.value("forAsk", std::string());
                if (!offerFor.empty() && !awaitingAsk(offerFor)) {
                    releaseItem(entry.id);
                    continue;
                }
                try {
                    startAnnouncedFetch(
                        fileOfferFromJson(body.at("offer")), message.fromFingerprint);
                } catch (const std::exception& error) {
                    bazarish::log::warn("file offer ignored: {}", error.what());
                }
            } else if (type == "file.cancel") {
                message.contentType = type;
                stopTransfer(body.value("fileId", std::string()), message.fromFingerprint,
                    body.value("ask", std::string()));
            } else if (type == "file.unavailable") {
                message.contentType = type;
                const std::string fileId = body.value("fileId", std::string());
                {
                    const std::lock_guard<std::mutex> lock(transfers_->mutex);
                    transfers_->pending.erase(fileId);
                }
                emitTransfer(fileId, TransferState::eFailed, 0, 0,
                    "the sender could not send this file", {}, message.fromFingerprint);
            } else if (type == "bot.command") {
                message.contentType = type;
                message.commandName = body.value("command", std::string());
                message.commandArgs = body.value("args", std::string());
                message.text = "/" + message.commandName
                    + (message.commandArgs.empty() ? std::string() : " " + message.commandArgs);
            } else if (type == "bot.callback") {
                message.contentType = type;
                message.callbackData = body.value("data", std::string());
                message.refId = body.value("ref", std::string());
            } else if (type == "edit") {
                message.contentType = type;
                message.refId = body.value("ref", std::string());
                message.text = body.value("text", std::string());
            } else if (type == "delete") {
                message.contentType = type;
                message.refId = body.value("ref", std::string());
            } else if (type == "receipt") {
                message.contentType = type;
                message.refId = body.value("ref", std::string());
            } else if (type == "reaction") {
                message.contentType = type;
                message.refId = body.value("ref", std::string());
                message.text = body.value("text", std::string());
                if (!reactionWithinLimits(message.text)) {
                    bazarish::log::info("oversized reaction from {} ignored",
                        bazarish::log::redact(message.fromFingerprint));
                    releaseItem(entry.id);
                    continue;
                }
            } else if (type == "call.invite" || type == "call.accept" || type == "call.decline"
                || type == "call.end" || type == "call.ring" || type == "call.taken") {
                handleCallSignal(type, message.fromFingerprint, body, message);
            } else if (type.rfind("device.", 0) == 0
                && message.fromFingerprint != fingerprint()) {
                bazarish::log::warn("sync: dropping a device message from {}",
                    bazarish::log::redact(message.fromFingerprint));
                noteWire(false, "device message from a contact", "dropped", type);
                releaseItem(entry.id);
                continue;
            } else if (type == "device.delegation-term") {
                message.contentType = type;
                if (body.value("device", std::string()) != client_->clientId()) {
                    const std::int64_t days = body.value("days", kDefaultDelegationDays);
                    if (days >= kMinDelegationDays && days <= kMaxDelegationDays
                        && days != delegationDays_) {
                        setDelegationDays(days, false);
                    }
                }
            } else if (type == "device.contacts-request") {
                message.contentType = type;
                if (body.value("device", std::string()) != client_->clientId()) {
                    sendContactBookTo(body.value("device", std::string()));
                }
            } else if (type == "device.contacts") {
                message.contentType = type;
                if (body.value("forDevice", std::string()) == client_->clientId()
                    && body.contains("contacts")) {
                    applyContactBook(body.at("contacts"));
                }
            } else if (type == "device.i2p-master-request") {
                message.contentType = type;
                const std::string wanted = body.value("host", std::string());
                const bool haveWanted = !i2pMaster_.empty()
                    && (wanted.empty() || i2pRoutingHost(i2pMaster_) == wanted);
                if (body.value("device", std::string()) != client_->clientId() && haveWanted) {
                    try {
                        syncI2pMasterToSelf();
                    } catch (const std::exception& error) {
                        log::info("could not answer a device asking for our address: {}",
                            error.what());
                    }
                }
            } else if (type == "device.alias-status") {
                message.contentType = type;
                if (message.fromFingerprint == fingerprint()
                    && resolverCoordinate_.configured()) {
                    try {
                        const AliasStatus status
                            = verifyAliasStatus(fromBase64(body.at("status").get<std::string>()),
                                fromBase64(body.at("delegation").get<std::string>()),
                                resolverCoordinate_.rootFingerprint, nowSeconds());
                        if (status.owner == fingerprint()
                            && status.issuedAt >= aliasStatusAt_) {
                            adoptAliasStatus(status);
                        }
                    } catch (const std::exception& error) {
                        log::info("a device's name answer was not accepted: {}", error.what());
                    }
                }
            } else if (type == "device.i2p-master") {
                message.contentType = type;
                if (message.fromFingerprint == fingerprint()) {
                    try {
                        const Bytes master
                            = fromBase64(body.at("i2pMaster").get<std::string>());
                        if (i2pMaster_.empty()) {
                            loadI2pDestination(master);
                        } else if (master != i2pMaster_) {
                            // Another device published a different address for this account.
                            const std::string offered = i2pRoutingHost(master);
                            if (client_->myDestination().dest == offered) {
                                replaceI2pMaster(master);
                                log::info("this account's address is now {}", offered);
                            } else {
                                log::info("ignoring an address another device sent: the "
                                          "server does not serve it");
                            }
                        }
                    } catch (const std::exception& error) {
                        bazarish::log::warn("master key from another device rejected: {}",
                            error.what());
                    }
                }
            } else if (type == "avatar") {
                message.contentType = type;
                try {
                    const nlohmann::json& av = body.at("avatar");
                    const Bytes data = fromBase64(av.value("data", std::string()));
                    storeContactAvatar(
                        message.fromFingerprint, data, av.value("mime", std::string()));
                    message.avatarData = std::string(data.begin(), data.end());
                } catch (const std::exception& error) {
                    bazarish::log::warn("contact avatar ignored: {}", error.what());
                }
            } else if (type == "device.avatar") {
                message.contentType = type;
                if (message.fromFingerprint == fingerprint()) {
                    try {
                        const nlohmann::json& av = body.at("avatar");
                        const Bytes data = fromBase64(av.value("data", std::string()));
                        storeOwnAvatar(data, av.value("mime", std::string()));
                        message.avatarData = std::string(data.begin(), data.end());
                    } catch (const std::exception& error) {
                        bazarish::log::warn("own avatar from another device ignored: {}",
                            error.what());
                    }
                }
            } else if (type == "device.contact-name") {
                message.contentType = type;
                if (message.fromFingerprint == fingerprint()) {
                    const auto named = contacts_.find(body.value("peer", std::string()));
                    if (named != contacts_.end()) {
                        named->second.displayName
                            = safeContactName(body.value("name", std::string()));
                    }
                }
            } else if (type == "device.chat-pin") {
                message.contentType = type;
                if (message.fromFingerprint == fingerprint()) {
                    message.refId = body.value("peer", std::string());
                    message.text
                        = body.value("pinned", false) ? std::string("1") : std::string("0");
                }
            } else if (type == "device.read") {
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    message.refId = body.value("peer", std::string());
                    message.text = std::to_string(body.value("ts", std::int64_t{0}));
                }
            } else if (type == "device.chat-clear") {
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    message.refId = body.value("peer", std::string());
                }
            } else if (type == "device.account-name") {
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    const std::string name = body.value("name", std::string());
                    if (!name.empty() && name.size() <= kMaxAccountNameBytes && name != name_) {
                        name_ = name;
                        client_->setDestinationOwner(destinationOwner());
                        persistMeta();
                    }
                    message.text = name_;
                }
            } else if (type == "device.account-prefs") {
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    const bool accept = body.value("acceptCalls", acceptCalls_);
                    const bool receipts = body.value("sendReceipts", sendReceipts_);
                    if (accept != acceptCalls_ || receipts != sendReceipts_) {
                        acceptCalls_ = accept;
                        sendReceipts_ = receipts;
                        persistMeta();
                    }
                }
            } else if (type == "device.saved-clear") {
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                }
            } else if (type == "device.contact-remove") {
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    message.refId = body.value("peer", std::string());
                    removeContact(message.refId);
                }
            } else if (type == "device.contact-block") {
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    message.refId = body.value("peer", std::string());
                    const bool blocked = body.value("blocked", false);
                    message.text = blocked ? std::string("1") : std::string("0");
                    if (!message.refId.empty()) {
                        if (blocked) {
                            blocked_.insert(message.refId);
                        } else {
                            blocked_.erase(message.refId);
                        }
                        persistBlocked();
                    }
                }
            } else if (type == "device.contact-accepted") {
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    message.refId = body.value("peer", std::string());
                    const auto known = contacts_.find(message.refId);
                    if (known != contacts_.end() && !known->second.issuedToThem) {
                        known->second.issuedToThem = true;
                        persistContacts();
                    }
                }
            } else if (type == "device.contact-prefs") {
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    message.refId = body.value("peer", std::string());
                    const auto known = contacts_.find(message.refId);
                    if (known != contacts_.end()) {
                        known->second.notifications = body.value("notifications", true);
                        known->second.allowCalls = body.value("allowCalls", true);
                        persistContacts();
                    }
                }
            } else if (type == "chat.clear") {
                message.contentType = type;
            } else if (type == "contact.accept") {
                message.contentType = type;
            } else if (type == "contact.routing") {
                message.contentType = type;
            } else {
                message.contentType = "unsupported";
                message.rawType = type;
            }

            if (body.contains("keyboard")) {
                message.keyboardJson = body.at("keyboard").dump();
            }
            if (body.contains("replyTo")) {
                message.replyTo = body.value("replyTo", std::string());
            }

            if (autoAckSurfaced) {
                releaseItem(entry.id);
            } else {
                message.pendingId = entry.id;
                awaitingAck_.insert(entry.id);
            }
            noteWire(false,
                (message.contentType.empty() ? std::string("content") : message.contentType)
                    + " from " + wireName(message.fromFingerprint),
                {}, "id " + entry.id.substr(0, std::min(entry.id.size(), kShortFingerprintChars)));
            result.push_back(std::move(message));
        } catch (const std::exception& error) {
            bazarish::log::warn(
                "sync: dropping unreadable pending item: {}", error.what());
            noteWire(false, "unreadable item", "dropped", error.what());
            releaseItem(entry.id);
        }
    }
    persistContacts();

    for (const std::string& peer : reaskedPeers) {
        try {
            acceptContactRequest(peer);
        } catch (const std::exception& error) {
            bazarish::log::warn("could not agree again to {}: {}",
                bazarish::log::redact(peer), error.what());
        }
    }

    for (const std::string& peer : establishedPeers) {
        maybeSendAvatarToContact(peer);
    }

    retryPendingRevokes();
    if (std::find(contactsAskedBy_.begin(), contactsAskedBy_.end(), client_->clientId())
        == contactsAskedBy_.end()) {
        contactsAskedBy_.push_back(client_->clientId());
        persistMeta();
        try {
            askDevicesForContacts();
        } catch (const std::exception& error) {
            bazarish::log::warn("sync: could not ask for the address book: {}", error.what());
        }
    }
    return result;
}

void Session::ackPending(const std::string& pendingId)
{
    forgetPending(pendingId);
    releasePending(pendingId);
}

void Session::onServerAnswered(std::function<void()> tell)
{
    serverAnswered_ = std::move(tell);
}

void Session::setAckSink(AckSink sink)
{
    ackSink_ = std::move(sink);
}

void Session::releaseItem(const std::string& pendingId)
{
    if (pendingId.empty()) {
        return;
    }
    if (!ackSink_) {
        client_->ack(pendingId);
        return;
    }
    awaitingAck_.insert(pendingId);
    ackSink_(pendingId);
}

std::vector<Session::MailboxItem> Session::fetchMailbox(
    Client& client, const std::vector<PendingEntry>& waiting, const std::size_t maxItems)
{
    std::vector<MailboxItem> items;
    for (const PendingEntry& entry : waiting) {
        if (maxItems > 0 && items.size() >= maxItems) {
            break;
        }
        try {
            items.push_back({entry.id, client.fetchBlob(entry.id)});
        } catch (const std::exception& error) {
            bazarish::log::info("mailbox item not fetched ahead: {}", error.what());
        }
    }
    return items;
}

void Session::holdFetched(std::vector<MailboxItem> items)
{
    fetched_.clear();
    for (MailboxItem& item : items) {
        fetched_.emplace(std::move(item.pendingId), std::move(item.blob));
    }
}

void Session::forgetPending(const std::string& pendingId)
{
    if (pendingId.empty()) {
        return;
    }
    awaitingAck_.erase(pendingId);
}

void Session::releasePending(const std::string& pendingId)
{
    if (pendingId.empty()) {
        return;
    }
    client_->ack(pendingId);
}

bool Session::canWriteTo(const std::string& peerFingerprint) const
{
    const auto known = contacts_.find(peerFingerprint);
    return known != contacts_.end() && !known->second.sendPass.empty();
}

namespace {

std::string pictureKey(const std::string& e2eId)
{
    return "picture:" + e2eId;
}

std::string voiceKey(const std::string& e2eId)
{
    return "voice:" + e2eId;
}

}  // namespace

void Session::putPicture(const std::string& e2eId, const Bytes& bytes)
{
    db_->put(pictureKey(e2eId), bytes);
}

std::optional<Bytes> Session::picture(const std::string& e2eId) const
{
    return db_->get(pictureKey(e2eId));
}

bool Session::hasPicture(const std::string& e2eId) const
{
    return db_->has(pictureKey(e2eId));
}

void Session::putVoice(const std::string& e2eId, const Bytes& bytes)
{
    db_->put(voiceKey(e2eId), bytes);
}

std::optional<Bytes> Session::voice(const std::string& e2eId) const
{
    return db_->get(voiceKey(e2eId));
}

std::vector<Client::DeviceEntry> Session::devices()
{
    return client_->listClients();
}

void Session::retireDevice(const std::string& clientId)
{
    client_->retireClient(clientId);
}

void Session::retireThisDevice()
{
    client_->retireClient(client_->clientId());
}

void Session::closeAccountOnServer()
{
    client_->closeAccount();
}

void Session::flushPendingEchoes()
{
    std::vector<std::pair<std::string, nlohmann::json>> ready;
    std::vector<std::string> established;
    std::vector<std::string> notEstablished;
    {
        const std::lock_guard<std::mutex> lock(echoQueue_->mutex);
        ready.swap(echoQueue_->pending);
        established.swap(echoQueue_->established);
        notEstablished.swap(echoQueue_->notEstablished);
    }
    for (const std::string& peerFingerprint : established) {
        const auto found = contacts_.find(peerFingerprint);
        if (found == contacts_.end() || found->second.issuedToThem) {
            continue;
        }
        found->second.issuedToThem = true;
        found->second.acceptInFlight = false;
        persistContacts();
        try {
            sendSelf({
                {"type", "device.contact-accepted"},
                {"peer", peerFingerprint},
            });
        } catch (const std::exception& error) {
            bazarish::log::warn("contact-accept self-sync failed: {}", error.what());
        }
        maybeSendAvatarToContact(peerFingerprint);
    }
    for (const std::string& peerFingerprint : notEstablished) {
        const auto found = contacts_.find(peerFingerprint);
        if (found != contacts_.end() && found->second.acceptInFlight) {
            found->second.acceptInFlight = false;
            bazarish::log::warn("the acceptance for {} did not land: the request stands",
                bazarish::log::redact(peerFingerprint));
        }
    }
    for (const auto& [peerFingerprint, inner] : ready) {
        try {
            echoSentToSelf(peerFingerprint, inner);
        } catch (const std::exception& error) {
            bazarish::log::warn(
                "could not echo what was sent to our own devices: {}", error.what());
        }
    }
}

void Session::echoSentToSelf(const std::string& peerFingerprint, const nlohmann::json& inner)
{
    if (myDest_.empty() || myServingKeyB64_.empty()) {
        return;
    }
    const nlohmann::json echo = envelope("device.message", toHex(randomBytes(16)), {
        {"peer", peerFingerprint},
        {"device", client_->clientId()},
        {"message", inner},
    });
    submitSignedToSelf(echo, "device.message", /*later=*/true);
}

void Session::askDevicesForContacts()
{
    const nlohmann::json inner = envelope("device.contacts-request", toHex(randomBytes(16)), {
        {"device", client_->clientId()},
    });
    submitSignedToSelf(inner, "device.contacts-request");
}

nlohmann::json Session::contactBookEntry(
    const std::string& peerFingerprint, const Contact& contact) const
{
    nlohmann::json entry = {
        {"peer", peerFingerprint},
        {"pass", contact.sendPass},
        {"sealing", contact.sealingPublicB64},
        {"dest", contact.dest},
        {"servingKey", contact.servingSealingB64},
        {"view", contact.view},
        {"sharingRefused", contact.sharingRefused},
        {"name", contact.displayName},
        {"notifications", contact.notifications},
        {"allowCalls", contact.allowCalls},
        {"issuedToThem", contact.issuedToThem},
        {"blocked", isBlocked(peerFingerprint)},
        {"identityClassical", contact.identityClassicalB64},
        {"identityPq", contact.identityPqB64},
    };
    if (!contact.avatar.empty()) {
        entry["avatar"] = toBase64(contact.avatar);
        entry["avatarMime"] = contact.avatarMime;
    }
    return entry;
}

void Session::sendContactBookTo(const std::string& toDevice)
{
    if (toDevice.empty() || contacts_.empty()) {
        return;
    }
    std::vector<nlohmann::json> chunk;
    std::size_t chunkBytes = 0;
    const auto flush = [&]() {
        if (chunk.empty()) {
            return;
        }
        const nlohmann::json inner = envelope("device.contacts", toHex(randomBytes(16)), {
            {"device", client_->clientId()},
            {"forDevice", toDevice},
            {"contacts", chunk},
        });
        submitSignedToSelf(inner, "device.contacts");
        chunk.clear();
        chunkBytes = 0;
    };
    for (const auto& [peerFingerprint, contact] : contacts_) {
        nlohmann::json entry = contactBookEntry(peerFingerprint, contact);
        std::size_t entryBytes = encodedBody(entry).size();
        if (entryBytes > kContactBookChunkBytes && entry.contains("avatar")) {
            entry.erase("avatar");
            entry.erase("avatarMime");
            entryBytes = encodedBody(entry).size();
        }
        if (chunkBytes + entryBytes > kContactBookChunkBytes) {
            flush();
        }
        chunkBytes += entryBytes;
        chunk.push_back(std::move(entry));
    }
    flush();
}

void Session::applyContactBook(const nlohmann::json& entries)
{
    bool changed = false;
    for (const nlohmann::json& entry : entries) {
        const std::string peerFingerprint = entry.value("peer", std::string());
        if (peerFingerprint.empty() || peerFingerprint == fingerprint()) {
            continue;
        }
        const bool isNew = contacts_.find(peerFingerprint) == contacts_.end();
        Contact& contact = contacts_[peerFingerprint];
        const auto fill = [](std::string& field, const std::string& value) {
            if (field.empty() && !value.empty()) {
                field = value;
            }
        };
        fill(contact.sealingPublicB64, entry.value("sealing", std::string()));
        fill(contact.dest, entry.value("dest", std::string()));
        fill(contact.servingSealingB64, entry.value("servingKey", std::string()));
        fill(contact.view, entry.value("view", std::string()));
        fill(contact.displayName, entry.value("name", std::string()));
        fill(contact.identityClassicalB64, entry.value("identityClassical", std::string()));
        fill(contact.identityPqB64, entry.value("identityPq", std::string()));
        if (isNew) {
            contact.sharingRefused = entry.value("sharingRefused", false);
            contact.notifications = entry.value("notifications", true);
            contact.allowCalls = entry.value("allowCalls", true);
            contact.issuedToThem = entry.value("issuedToThem", false);
            contact.sendPass = entry.value("pass", std::string());
            if (entry.value("blocked", false)) {
                blocked_.insert(peerFingerprint);
            }
        }
        if (contact.avatar.empty() && entry.contains("avatar")) {
            storeContactAvatar(peerFingerprint, fromBase64(entry.at("avatar").get<std::string>()),
                entry.value("avatarMime", std::string()));
        }
        changed = true;
    }
    if (changed) {
        persistContacts();
        db_->putText("blocked", nlohmann::json(blocked_).dump());
    }
}

void Session::setAudioBackend(AudioSourceFactory sourceFactory, AudioSinkFactory sinkFactory)
{
    audioSourceFactory_ = std::move(sourceFactory);
    audioSinkFactory_ = std::move(sinkFactory);
}

std::shared_ptr<bazarish::i2p::Endpoint> Session::openCallMediaSession()
{
    bazarish::i2p::EndpointConfig config;
    config.privacy = bazarish::i2p::Privacy::eMinimal;
    config.published = true;
    config.label = "Call media";
    config.owner = destinationOwner();
    config.traffic = bazarish::i2p::Traffic::eRaw;
    config.realtime = true;
    return i2pRouter().createEndpoint(config);
}

void Session::startCallMedia()
{
    call_.transport = std::make_unique<I2pCallTransport>(*call_.dgram, call_.peerMediaDest);
    std::unique_ptr<AudioSource> audioSource
        = audioSourceFactory_ ? audioSourceFactory_() : std::make_unique<SineAudioSource>();
    std::unique_ptr<AudioSink> audioSink
        = audioSinkFactory_ ? audioSinkFactory_() : std::make_unique<CapturingAudioSink>();
    call_.media = std::make_unique<CallMedia>(*call_.transport, std::move(audioSource),
        std::move(audioSink), call_.mediaKey,
        call_.initiator ? CallRole::eCaller : CallRole::eCallee);
    call_.media->setMuted(call_.muted);
    call_.media->setOnConnected([this]() {
        if (call_.connectedAtMs == 0) {
            call_.connectedAtMs = nowMillis();
            call_.stage.clear();
        }
    });
    bazarish::log::info("call media: from {} to {}",
        bazarish::log::redact(call_.dgram->routingHost()),
        bazarish::log::redact(call_.peerMediaDest));
    call_.media->start();
}

void Session::clearCall()
{
    if (call_.media) {
        bazarish::log::info("call media: {} datagrams sent, {} received",
            call_.media->packetsSent(), call_.media->packetsReceived());
        call_.media->stop();
    }
    call_.media.reset();
    call_.transport.reset();
    call_.dgram.reset();
    call_.state = CallState::eIdle;
    call_.callId.clear();
    call_.peerFingerprint.clear();
    call_.peerMediaDest.clear();
    call_.mediaKey.clear();
    call_.initiator = false;
    call_.muted = false;
    call_.startedAtMs = 0;
    call_.peerRingingAtMs = 0;
    call_.connectedAtMs = 0;
    call_.lastPacketsReceived = 0;
    call_.lastPacketAtMs = 0;
}

void Session::announceCallTaken(const std::string& callId)
{
    const nlohmann::json inner = envelope("call.taken", toHex(randomBytes(16)), {
        {"device", client_->clientId()},
        {"callId", callId},
    });
    try {
        submitSignedToSelf(inner, "call.taken");
    } catch (const std::exception& error) {
        bazarish::log::warn("other devices not told the call was taken: {}", error.what());
    }
}

bool Session::sendCallSignal(
    const std::string& peerFingerprint, const std::string& type, nlohmann::json extra)
{
    nlohmann::json inner = envelope(type, toHex(randomBytes(8)));
    for (const auto& field : extra.items()) {
        inner[field.key()] = field.value();
    }
    return sendContent(peerFingerprint, std::move(inner));
}

void Session::startCall(const std::string& peerFingerprint)
{
    if (call_.state != CallState::eIdle) {
        throw std::runtime_error("a call is already in progress");
    }
    if (contacts_.find(peerFingerprint) == contacts_.end()) {
        throw std::runtime_error("unknown contact: " + peerFingerprint);
    }
    call_.stage = "Preparing your call address";
    auto dgram = openCallMediaSession();
    const std::string callId = toHex(randomBytes(8));
    const Bytes mediaKey = randomBytes(kAeadKeyBytes);
    const bool delivered = sendCallSignal(peerFingerprint, "call.invite",
        {
            {"callId", callId},
                    {"dest", dgram->routingHost()},
            {"key", toBase64(mediaKey)},
        });
    call_.state = CallState::eOutgoing;
    call_.callId = callId;
    call_.peerFingerprint = peerFingerprint;
    call_.mediaKey = mediaKey;
    call_.initiator = true;
    call_.muted = false;
    call_.startedAtMs = nowMillis();
    call_.invitedAtMs = call_.startedAtMs;
    call_.deliveredAtMs = 0;
    call_.dgram = std::move(dgram);
    if (delivered) {
        call_.deliveredAtMs = nowMillis();
        call_.stage = kCallDeliveredStage;
    } else {
        call_.stage = "Delivering the invitation";
    }
}

void Session::startAudioCall(const std::string& peerFingerprint)
{
    startCall(peerFingerprint);
}

void Session::acceptCall(const std::string& callId)
{
    if (call_.state != CallState::eIncoming || call_.callId != callId) {
        throw std::runtime_error("no matching incoming call");
    }
    auto dgram = openCallMediaSession();
    sendCallSignal(call_.peerFingerprint, "call.accept",
        {{"callId", callId}, {"dest", dgram->routingHost()}});
    announceCallTaken(callId);
    call_.dgram = std::move(dgram);
    call_.state = CallState::eActive;
    call_.stage = kCallOpeningStage;
    startCallMedia();
}

void Session::setAcceptCalls(const bool accept)
{
    if (acceptCalls_ == accept) {
        return;
    }
    acceptCalls_ = accept;
    persistMeta();
    syncAccountPrefsToSelf();
}

void Session::setSendReceipts(const bool on)
{
    if (sendReceipts_ == on) {
        return;
    }
    sendReceipts_ = on;
    persistMeta();
    syncAccountPrefsToSelf();
}

void Session::syncAccountPrefsToSelf()
{
    try {
        sendSelf({
            {"type", "device.account-prefs"},
            {"acceptCalls", acceptCalls_},
            {"sendReceipts", sendReceipts_},
        });
    } catch (const std::exception& error) {
        bazarish::log::warn("account-prefs self-sync failed: {}", error.what());
    }
}

void Session::declineCall(const std::string& callId)
{
    if (call_.state != CallState::eIncoming || call_.callId != callId) {
        throw std::runtime_error("no matching incoming call");
    }
    const std::string peer = call_.peerFingerprint;
    logCompletedCall(CallOutcome::eDeclined);
    clearCall();
    announceCallTaken(callId);
    try {
        sendCallSignal(peer, "call.decline", {{"callId", callId}, {"reason", "declined"}});
    } catch (const std::exception& error) {
        bazarish::log::warn("decline signal not delivered: {}", error.what());
    }
}

void Session::endCall()
{
    if (call_.state == CallState::eIdle) {
        return;
    }
    const std::string peer = call_.peerFingerprint;
    const std::string callId = call_.callId;
    const CallOutcome outcome = call_.state == CallState::eActive
        ? CallOutcome::eAnswered
        : (call_.initiator ? CallOutcome::eCancelled : CallOutcome::eDeclined);
    logCompletedCall(outcome);
    clearCall();
    try {
        sendCallSignal(peer, "call.end", {{"callId", callId}});
    } catch (const std::exception& error) {
        bazarish::log::warn("end signal not delivered: {}", error.what());
    }
}

void Session::setCallMuted(const bool muted)
{
    call_.muted = muted;
    if (call_.media) {
        call_.media->setMuted(muted);
    }
}

Session::CallInfo Session::currentCall() const
{
    CallInfo info;
    info.state = call_.state;
    info.callId = call_.callId;
    info.peerFingerprint = call_.peerFingerprint;
    info.muted = call_.muted;
    info.stage = call_.stage;
    if (call_.media) {
        info.inputLevel = call_.media->inputLevel();
        info.outputLevel = call_.media->outputLevel();
    }
    info.peerRinging = call_.peerRingingAtMs > 0;
    info.connectedAtMs = call_.connectedAtMs;
    if (call_.media) {
        info.packetsSent = call_.media->packetsSent();
        info.packetsReceived = call_.media->packetsReceived();
    }
    return info;
}

void Session::handleCallSignal(const std::string& type, const std::string& from,
    const nlohmann::json& body, IncomingMessage& message)
{
    message.contentType = type;
    message.callId = body.value("callId", std::string());

    if (type == "call.invite") {
        const std::int64_t sentAt = body.value("sentAt", static_cast<std::int64_t>(0));
        if (sentAt > 0 && nowMillis() - sentAt > kRingTimeoutMs) {
            bazarish::log::info("call invite ignored: it is {} ms old",
                nowMillis() - sentAt);
            return;
        }
        if (std::find(endedCalls_.begin(), endedCalls_.end(), message.callId)
            != endedCalls_.end()) {
            bazarish::log::info("call invite ignored: that call is already over");
            return;
        }
        if (call_.state != CallState::eIdle && call_.callId == message.callId) {
            bazarish::log::info("duplicate call invite ignored");
            return;
        }
        if (!acceptCalls_ || !contactCalls(from)) {
            try {
                sendCallSignal(
                    from, "call.decline", {{"callId", message.callId}, {"reason", "refused"}});
            } catch (const std::exception& error) {
                bazarish::log::warn("refusal not delivered: {}", error.what());
            }
            pendingCallLog_.push_back({from, true, CallOutcome::eRefusedHere, 0});
            message.text = "refused";
            return;
        }
        if (call_.state != CallState::eIdle) {
            try {
                sendCallSignal(
                    from, "call.decline", {{"callId", message.callId}, {"reason", "busy"}});
            } catch (const std::exception& error) {
                bazarish::log::warn("busy signal not delivered: {}", error.what());
            }
            pendingCallLog_.push_back({from, true, CallOutcome::eMissed, 0});
            message.text = "busy";
            return;
        }
        Bytes key;
        try {
            key = fromBase64(body.value("key", std::string()));
        } catch (const std::exception& error) {
            bazarish::log::warn("call invite dropped, key unreadable: {}", error.what());
            return;
        }
        if (key.size() != kAeadKeyBytes) {
            return;
        }
        call_.state = CallState::eIncoming;
        call_.callId = message.callId;
        call_.peerFingerprint = from;
        call_.peerMediaDest = body.value("dest", std::string());
        call_.mediaKey = std::move(key);
        call_.initiator = false;
        call_.muted = false;
        call_.startedAtMs = nowMillis();
        try {
            sendCallSignal(from, "call.ring", {{"callId", message.callId}});
        } catch (const std::exception& error) {
            bazarish::log::warn("ring signal not delivered: {}", error.what());
        }
        return;
    }

    if (type == "call.ring") {
        if (call_.state == CallState::eOutgoing && call_.callId == message.callId
            && from == call_.peerFingerprint) {
            call_.peerRingingAtMs = nowMillis();
            call_.stage = kCallAlertingStage;
        }
        return;
    }

    if (type == "call.taken") {
        // Another device of this account answered or declined the very call this one is showing.
        if (body.value("device", std::string()) != client_->clientId()
            && call_.state == CallState::eIncoming && call_.callId == message.callId) {
            clearCall();
        }
        return;
    }

    if (type == "call.accept") {
        if (call_.state == CallState::eOutgoing && call_.callId == message.callId
            && from == call_.peerFingerprint) {
            call_.peerMediaDest = body.value("dest", std::string());
            call_.state = CallState::eActive;
            call_.stage = kCallOpeningStage;
            startCallMedia();
        }
        return;
    }

    if (!message.callId.empty()) {
        endedCalls_.push_back(message.callId);
        if (endedCalls_.size() > kEndedCallsRemembered) {
            endedCalls_.pop_front();
        }
    }
    if (call_.state != CallState::eIdle && call_.callId == message.callId
        && from == call_.peerFingerprint) {
        if (type == "call.decline" && call_.state != CallState::eOutgoing) {
            return;
        }
        CallOutcome outcome;
        if (type == "call.decline") {
            const std::string reason = body.value("reason", std::string());
            if (reason == "busy") {
                outcome = CallOutcome::eBusy;
            } else if (reason == "refused") {
                outcome = CallOutcome::eRefused;
            } else {
                outcome = CallOutcome::eDeclined;
            }
        } else if (call_.state == CallState::eActive) {
            outcome = CallOutcome::eAnswered;
        } else if (call_.state == CallState::eIncoming) {
            outcome = CallOutcome::eMissed;
        } else {
            outcome = CallOutcome::eDeclined;
        }
        logCompletedCall(outcome);
        clearCall();
    }
}

void Session::logCompletedCall(const CallOutcome outcome)
{
    if (call_.peerFingerprint.empty()) {
        return;
    }
    const std::int64_t durationSec
        = (outcome == CallOutcome::eAnswered && call_.connectedAtMs > 0)
        ? (nowMillis() - call_.connectedAtMs) / 1000
        : 0;
    pendingCallLog_.push_back(
        CompletedCall{call_.peerFingerprint, !call_.initiator, outcome, durationSec});
}

std::vector<Session::CompletedCall> Session::takeCallLog()
{
    std::vector<CompletedCall> out = std::move(pendingCallLog_);
    pendingCallLog_.clear();
    return out;
}

void Session::tickCalls()
{
    if (call_.startedAtMs == 0) {
        return;
    }
    if (call_.state == CallState::eOutgoing && call_.deliveredAtMs == 0) {
        if (nowMillis() - call_.invitedAtMs <= kInviteDeliveryTimeoutMs) {
            return;
        }
        const std::string peer = call_.peerFingerprint;
        logCompletedCall(CallOutcome::eNoAnswer);
        clearCall();
        bazarish::log::warn("call invitation to {} never reached their server",
            bazarish::log::redact(peer));
        return;
    }
    if (call_.state == CallState::eActive && call_.media) {
        const std::uint64_t received = call_.media->packetsReceived();
        if (received != call_.lastPacketsReceived) {
            call_.lastPacketsReceived = received;
            call_.lastPacketAtMs = nowMillis();
        } else if (call_.lastPacketAtMs > 0
            && nowMillis() - call_.lastPacketAtMs > kMediaSilenceTimeoutMs) {
            const std::string peer = call_.peerFingerprint;
            logCompletedCall(CallOutcome::eAnswered);
            clearCall();
            bazarish::log::info("call with {} ended: media went silent",
                bazarish::log::redact(peer));
            return;
        }
    }
    const std::int64_t since = call_.peerRingingAtMs > 0 ? call_.peerRingingAtMs
        : (call_.deliveredAtMs > 0 ? call_.deliveredAtMs : call_.startedAtMs);
    if (nowMillis() - since <= kRingTimeoutMs) {
        return;
    }
    if (call_.state == CallState::eOutgoing) {
        const std::string peer = call_.peerFingerprint;
        const std::string callId = call_.callId;
        logCompletedCall(CallOutcome::eNoAnswer);
        clearCall();
        try {
            sendCallSignal(peer, "call.end", {{"callId", callId}});
        } catch (const std::exception& error) {
            bazarish::log::warn("end signal not delivered: {}", error.what());
        }
    } else if (call_.state == CallState::eIncoming) {
        logCompletedCall(CallOutcome::eMissed);
        clearCall();
    }
}

DestinationInfo Session::serverDestination()
{
    return client_->myDestination();
}

bool Session::hasOwnRouting() const
{
    return !myDest_.empty() && !myServingKeyB64_.empty();
}

void Session::refreshOwnCard()
{
    if (cardB64_.empty()) {
        throw std::runtime_error("not registered: nothing to refresh");
    }
    storeCard(client_->publishCard(sealingKey_.publicDer(), ownRoutingHost(), currentCardIssuedAt()));
}

std::string Session::contactInviteUri(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        throw std::runtime_error("not a contact");
    }
    if (found->second.dest.empty() || found->second.servingSealingB64.empty()) {
        throw std::runtime_error("no routing held for this contact yet");
    }
    if (!isViewCapability(found->second.view)) {
        throw std::runtime_error(
            "no descriptor key for this contact yet - it arrives with their next message");
    }
    Descriptor descriptor;
    descriptor.fingerprint = peerFingerprint;
    descriptor.dest = found->second.dest;
    descriptor.view = found->second.view;
    descriptor.name = found->second.displayName;
    return encodeDescriptor(descriptor);
}

std::string Session::destinationOwner() const
{
    constexpr std::size_t kOwnerFingerprintChars = 8;
    return name_.empty() ? fingerprint().substr(0, kOwnerFingerprintChars) : name_;
}

std::string Session::inviteUri() const
{
    if (myDest_.empty() || view_.empty()) {
        throw std::runtime_error("register first: no destination to publish");
    }
    Descriptor descriptor;
    descriptor.fingerprint = fingerprint();
    descriptor.dest = myDest_;
    descriptor.view = view_;
    descriptor.name = name_;
    return encodeDescriptor(descriptor);
}

void Session::scheduleNextAliasCheck(const std::int64_t from)
{
    aliasCheckAfter_ = from + kAliasStatusIntervalSeconds
        + static_cast<std::int64_t>(randomBelow(kAliasStatusJitterSeconds));
}

void Session::adoptAliasStatus(const AliasStatus& status)
{
    aliasNames_.clear();
    for (const AliasStatusEntry& entry : status.names) {
        aliasNames_.push_back(AliasHolding{
            entry.alias, entry.notAfter, entry.autoRenew, entry.bindingWanted, entry.bound});
    }
    aliasDepositCovers_ = status.depositCoversRenewals;
    aliasStatusAt_ = status.issuedAt;
    scheduleNextAliasCheck(status.issuedAt);
    persistMeta();
}

void Session::relayAliasStatus(const Bytes& statusDer, const Bytes& delegationDer)
{
    const nlohmann::json inner = envelope("device.alias-status",
        toHex(randomBytes(kRequestIdBytes)), {
        {"status", toBase64(statusDer)},
        {"delegation", toBase64(delegationDer)},
    });
    submitSignedToSelf(inner, "device.alias-status");
}

namespace {

Session::AliasStatusAnswer askAliasStatus(const Session::AliasErrandContext& context,
    const Identity& identity, const FetchTransport& over, const std::int64_t now)
{
    AliasMaintenanceRequest asking;
    asking.op = kAliasStatusOp;
    asking.issuedAt = now;
    const Bytes request = signAliasMaintenanceRequest(asking, identity);
    const FetchOutcome outcome = over(context.resolver.dest, kAliasStatusOp, request);
    if (!outcome.ok) {
        log::info("the alias registry refused a status ask: {}",
            outcome.errorCode.empty() ? std::string("no answer") : outcome.errorCode);
        const std::optional<ErrorCode> known = errorCodeFromString(outcome.errorCode);
        throw std::runtime_error(known ? std::string(readable(*known))
                                       : "The alias registry did not answer.");
    }
    const ResolveResponse answer = resolveResponseFromJson(nlohmann::json::parse(outcome.sealed));
    Session::AliasStatusAnswer out;
    out.status = verifyAliasStatus(
        answer.recordDer, answer.delegationDer, context.resolver.rootFingerprint, now);
    if (out.status.owner != context.fingerprint) {
        throw std::runtime_error("the name service answered about another account");
    }
    out.recordDer = answer.recordDer;
    out.delegationDer = answer.delegationDer;
    return out;
}

bool tellAliasesWhereWeAre(const Session::AliasErrandContext& context, const Identity& identity,
    const FetchTransport& over, const std::vector<Session::AliasHolding>& names,
    const std::int64_t now)
{
    Descriptor descriptor;
    descriptor.fingerprint = context.fingerprint;
    descriptor.dest = context.dest;
    descriptor.view = context.view;

    const bool moved = context.pushedDest != context.dest || context.pushedView != context.view;
    std::size_t needed = 0;
    std::size_t accepted = 0;
    for (const Session::AliasHolding& holding : names) {
        if (!holding.bindingWanted || (holding.bound && !moved)) {
            continue;
        }
        ++needed;
        AliasMaintenanceRequest asking;
        asking.op = kAliasUpdateOp;
        asking.alias = holding.alias;
        asking.descriptor = descriptor;
        asking.aliasCertDer
            = AliasCertificate::issue(identity, holding.alias, now);
        asking.issuedAt = now;
        const Bytes request = signAliasMaintenanceRequest(asking, identity);
        try {
            const FetchOutcome outcome = over(context.resolver.dest, kAliasUpdateOp, request);
            if (!outcome.ok) {
                log::info("name {} not repointed yet: {}", holding.alias,
                    outcome.errorCode.empty() ? std::string("no answer") : outcome.errorCode);
                continue;
            }
            ++accepted;
        } catch (const std::exception& error) {
            log::info("name {} not repointed yet: {}", holding.alias, error.what());
        }
    }
    return needed != 0 && accepted == needed;
}

FetchTransport heldDestFor(
    const bool i2pEnabled, const bazarish::i2p::Privacy privacy, const std::string& owner)
{
    if (!i2pEnabled) {
        throw std::runtime_error("The alias registry is reached over I2P, and I2P is "
                                 "switched off.");
    }
    bazarish::i2p::Router* const router = sharedI2pRouterIfRunning();
    if (router == nullptr || !router->ready()) {
        throw std::runtime_error("The I2P router is still building tunnels.");
    }
    return resolverHeldDest(*router, privacy, owner);
}

}  // namespace

FetchTransport Session::heldTransport() const
{
    if (fetchTransportOverride_) {
        return fetchTransportOverride_;
    }
    return heldDestFor(i2pEnabled(), transferPrivacy(), destinationOwner());
}

bool Session::refreshAliasStatus(const FetchTransport& over)
{
    if (!resolverCoordinate_.configured()) {
        return false;
    }
    const AliasStatusAnswer answer = askAliasStatus(aliasErrandContext(), client_->identity(),
        over ? over : fetchTransport(), nowSeconds());
    adoptAliasStatus(answer.status);
    try {
        relayAliasStatus(answer.recordDer, answer.delegationDer);
    } catch (const std::exception& error) {
        log::info("could not hand the name answer to this account's other devices: {}",
            error.what());
    }
    return true;
}

bool Session::aliasUpdatePending() const
{
    if (myDest_.empty() || !isViewCapability(view_)) {
        return false;
    }
    const bool moved = aliasPushedDest_ != myDest_ || aliasPushedView_ != view_;
    for (const AliasHolding& holding : aliasNames_) {
        if (holding.bindingWanted && (moved || !holding.bound)) {
            return true;
        }
    }
    return false;
}

bool Session::aliasServicingDue() const
{
    if (!resolverCoordinate_.configured() || aliasNames_.empty()) {
        return false;
    }
    return aliasUpdatePending() || nowSeconds() >= aliasCheckAfter_;
}

bool Session::pushAliasDescriptor(const FetchTransport& over)
{
    if (!aliasUpdatePending()) {
        return false;
    }
    if (!tellAliasesWhereWeAre(aliasErrandContext(), client_->identity(),
            over ? over : fetchTransport(), aliasNames_, nowSeconds())) {
        return false;
    }
    aliasPushedDest_ = myDest_;
    aliasPushedView_ = view_;
    noteAliasesBound();
    persistMeta();
    return true;
}

Session::AliasErrandContext Session::aliasErrandContext() const
{
    AliasErrandContext context;
    context.identityPem = client_->identity().privatePem();
    context.resolver = resolverCoordinate_;
    context.i2pEnabled = i2pEnabled();
    context.privacy = transferPrivacy();
    context.destinationOwner = destinationOwner();
    context.fingerprint = fingerprint();
    context.dest = myDest_;
    context.view = view_;
    context.pushedDest = aliasPushedDest_;
    context.pushedView = aliasPushedView_;
    context.transport = fetchTransportOverride_;
    return context;
}

Session::AliasErrandResult Session::runAliasErrand(const AliasErrandContext& context)
{
    AliasErrandResult out;
    if (!context.resolver.configured()) {
        out.error = "This build has no alias registry configured.";
        return out;
    }
    try {
        const FetchTransport over = context.transport
            ? context.transport
            : heldDestFor(context.i2pEnabled, context.privacy, context.destinationOwner);
        const std::int64_t now = nowSeconds();
        out.answer = askAliasStatus(context, Identity::fromPrivatePem(context.identityPem),
            over, now);
        out.haveStatus = true;

        std::vector<AliasHolding> names;
        for (const AliasStatusEntry& entry : out.answer.status.names) {
            names.push_back(AliasHolding{
                entry.alias, entry.notAfter, entry.autoRenew, entry.bindingWanted, entry.bound});
        }
        const bool canPublish = !context.dest.empty() && isViewCapability(context.view);
        const bool moved
            = context.pushedDest != context.dest || context.pushedView != context.view;
        const bool anyNeeded = std::any_of(names.begin(), names.end(),
            [moved](const AliasHolding& holding) {
                return holding.bindingWanted && (moved || !holding.bound);
            });
        if (anyNeeded && canPublish) {
            out.pointed = tellAliasesWhereWeAre(
                context, Identity::fromPrivatePem(context.identityPem), over, names, now);
            if (out.pointed) {
                out.pushedDest = context.dest;
                out.pushedView = context.view;
            }
        }
        out.ok = true;
    } catch (const std::exception& error) {
        out.error = error.what();
    }
    return out;
}

void Session::applyAliasErrand(const AliasErrandResult& result)
{
    if (result.haveStatus) {
        adoptAliasStatus(result.answer.status);
        try {
            relayAliasStatus(result.answer.recordDer, result.answer.delegationDer);
        } catch (const std::exception& error) {
            log::info("could not hand the name answer to this account's other devices: {}",
                error.what());
        }
    }
    if (result.pointed) {
        aliasPushedDest_ = result.pushedDest;
        aliasPushedView_ = result.pushedView;
        noteAliasesBound();
        persistMeta();
    }
}

void Session::noteAliasesBound()
{
    for (AliasHolding& holding : aliasNames_) {
        if (holding.bindingWanted) {
            holding.bound = true;
        }
    }
}

void Session::serviceAliases()
{
    if (!resolverCoordinate_.configured() || aliasNames_.empty()) {
        return;
    }
    try {
        const bool pushing = aliasUpdatePending();
        const bool asking = nowSeconds() >= aliasCheckAfter_;
        if (!pushing && !asking) {
            return;
        }
        const FetchTransport over = heldTransport();
        if (pushing) {
            pushAliasDescriptor(over);
        }
        if (asking) {
            refreshAliasStatus(over);
        }
    } catch (const std::exception& error) {
        log::info("name servicing will try again: {}", error.what());
    }
}

void Session::serviceAliasesAfterMove()
{
    if (!resolverCoordinate_.configured()) {
        return;
    }
    try {
        if (aliasNames_.empty()) {
            refreshAliasStatus();
        }
        if (aliasUpdatePending()) {
            pushAliasDescriptor();
        }
    } catch (const std::exception& error) {
        log::info("the name service was not reached after this account moved: {}", error.what());
    }
}

void Session::changePassphrase(const std::string& passphrase)
{
    db_->rekey(passphrase);
    encrypted_ = !passphrase.empty();
    persistMeta();
}

void Session::exportAccount(const fs::path& outFile, const std::string& password)
{
    const nlohmann::json meta = nlohmann::json::parse(db_->text("meta"));
    nlohmann::json contacts = contactsToJson();

    nlohmann::json avatars = nlohmann::json::object();
    for (const auto& [contactFp, contact] : contacts_) {
        if (!contact.avatar.empty()) {
            avatars[contactFp] = toBase64(contact.avatar);
        }
    }
    const nlohmann::json bundle = {
        {"v", kBundleFormatVersion},
        {"identityPem", client_->identity().privatePem()},
        {"sealingPem", sealingKey_.privatePem()},
        {"i2pMaster", toBase64(i2pMaster_)},
        {"meta", meta},
        {"contacts", contacts},
        {"avatar", toBase64(avatar_)},
        {"contactAvatars", avatars},
        {"blocked", nlohmann::json(blocked_)},
    };
    const std::string text = bundle.dump();
    const Bytes sealed = cms::sealWithPassword(Bytes(text.begin(), text.end()), password);
    writeFileText(outFile, std::string(sealed.begin(), sealed.end()));
}

void Session::importAccount(const fs::path& bundleFile, const fs::path& accountFile,
    const std::string& password, const std::string& atRestPassphrase)
{
    const std::string sealedText = readFileText(bundleFile);
    const Bytes plain
        = cms::unsealWithPassword(Bytes(sealedText.begin(), sealedText.end()), password);
    const nlohmann::json bundle = nlohmann::json::parse(plain.begin(), plain.end());

    if (bundle.value("v", kBundleFormatVersion) > kBundleFormatVersion) {
        throw std::runtime_error("this backup was written by a newer version of Bazarish");
    }
    AccountDb db(accountFile, atRestPassphrase);
    const Identity identity = Identity::fromPrivatePem(bundle.at("identityPem").get<std::string>());
    const Key sealing = Key::fromPrivatePem(bundle.at("sealingPem").get<std::string>());
    db.putText("identity.pem", identity.privatePem());
    db.putText("sealing.pem", sealing.privatePem());

    nlohmann::json meta = bundle.at("meta");
    meta["encrypted"] = !atRestPassphrase.empty();
    meta["clientId"] = toHex(randomBytes(8));

    db.putText("meta", meta.dump(2));
    db.putText("contacts", bundle.at("contacts").dump());
    if (bundle.contains("blocked")) {
        db.putText("blocked", bundle.at("blocked").dump());
    }
    if (bundle.contains("i2pMaster")) {
        const Bytes master = fromBase64(bundle.at("i2pMaster").get<std::string>());
        if (!master.empty()) {
            db.put("i2p-master", master);
        }
    }
    if (bundle.contains("avatar")) {
        const Bytes avatar = fromBase64(bundle.at("avatar").get<std::string>());
        if (!avatar.empty()) {
            db.put("avatar.self", avatar);
        }
    }
    if (bundle.contains("contactAvatars")) {
        for (const auto& [contactFp, encoded] : bundle.at("contactAvatars").items()) {
            const Bytes avatar = fromBase64(encoded.get<std::string>());
            if (!avatar.empty()) {
                db.put("avatar-" + contactFp, avatar);
            }
        }
    }
}

}  // namespace bazarish::client
