// Bazarish project (c) 2026
#include "Session.hpp"

#include "LoginSigner.hpp"

#include "AccountDb.hpp"

#include "Authorship.hpp"
#include "DevicePairing.hpp"
#include "FederationFetch.hpp"
#include "I2pKeys.hpp"
#include "I2pRouter.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/PathText.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Hybrid.hpp>
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
#include <array>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
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
const char* const kTypeChatTimer = "chat.timer";
const char* const kTypeImage = "image";
const char* const kTypeAudio = "audio";
constexpr std::size_t kDeliveryIdBytes = 16;
constexpr std::size_t kContactBookChunkBytes = 128 * 1024;
constexpr std::size_t kRequestIdBytes = 8;

constexpr std::int64_t kRegistryFanoutRetrySeconds = 10;

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
constexpr const char* kChosenNamesKey = "chosen-contact-names";

constexpr std::size_t kDeliveryIdSeedBytes = 32;

namespace fs = std::filesystem;

fs::path i2pDirFor(const fs::path& accountFile)
{
    return accountFile.parent_path().parent_path() / "i2p";
}

constexpr std::int64_t kMediaSilenceTimeoutMs = 20000;
constexpr std::size_t kEndedCallsRemembered = 32;

constexpr int kMessageFormatVersion = 1;
constexpr int kBundleFormatVersion = 2;

constexpr char kPresenceKeyRow[] = "presence.pem";
constexpr char kPresenceDestRow[] = "presence-dest";
constexpr char kAddressSealingRow[] = "address-sealing.pem";
constexpr char kAddressSigningRow[] = "address-signing.pem";

void applyPresence(Contact& contact, const AccountKind kind, const std::string& presenceKeyB64,
    const std::string& presenceDest)
{
    contact.kind = kind;
    if (kind != AccountKind::eUser) {
        contact.presenceKeyB64.clear();
        contact.presenceDest.clear();
        return;
    }
    const Key key = Key::fromPublicDer(fromBase64(presenceKeyB64));
    if (key.hasKem() || !key.isA(kClassicalSealingAlgorithm)) {
        throw std::runtime_error("a presence key is a bare X25519 key");
    }
    validateB32I2pHost(presenceDest);
    contact.presenceKeyB64 = presenceKeyB64;
    contact.presenceDest = presenceDest;
}

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

nlohmann::json readBundle(const Bytes& plain)
{
    const nlohmann::json bundle = nlohmann::json::parse(plain.begin(), plain.end());
    const int version = bundle.at("v").get<int>();
    if (version > kBundleFormatVersion) {
        throw std::runtime_error("this backup was written by a newer version of Bazarish");
    }
    if (version < kBundleFormatVersion) {
        throw std::runtime_error("this backup was written by an older version of Bazarish");
    }
    return bundle;
}

void applyBootstrap(Contact& contact, const nlohmann::json& bootstrap)
{
    applyPresence(contact, accountKindFromName(bootstrap.at("kind").get<std::string>()),
        bootstrap.value("presenceKey", std::string()), bootstrap.value("presenceDest", std::string()));
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
constexpr std::size_t kHashChunkBytes = 64 * 1024;
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

const char* const kGroupKindGroup = "group";
const char* const kGroupKindChannel = "channel";
const char* const kTypeGroupState = "group.state";
const char* const kTypeGroupReactions = "group.reactions";

nlohmann::json imageBody(const std::string& name, const std::string& mime, const Bytes& bytes)
{
    return {
        {"name", name},
        {"mime", mime},
        {"size", bytes.size()},
        {"data", nlohmann::json::binary(bytes)},
    };
}

nlohmann::json audioBody(const std::int64_t durationMs, const Bytes& opus)
{
    return {
        {"durationMs", durationMs},
        {"size", opus.size()},
        {"data", nlohmann::json::binary(opus)},
    };
}

bool echoesToOwnDevices(const std::string& type)
{
    static const std::set<std::string> kEchoed{
        "text", "image", "audio", "edit", "delete", "reaction", "chat.clear", "chat.timer"};
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

std::optional<std::int64_t> callAnswerDeadline(
    const std::int64_t sentAtMs, const std::int64_t arrivedAtMs)
{
    if (arrivedAtMs - sentAtMs >= kCallAnswerWindowMs) {
        return std::nullopt;
    }
    // A callee's clock behind the caller's does not lengthen the ring.
    return std::min(sentAtMs, arrivedAtMs) + kCallAnswerWindowMs;
}

bool isChatTimerChoice(const std::int64_t seconds)
{
    return std::find(kChatTimerChoices.begin(), kChatTimerChoices.end(), seconds)
        != kChatTimerChoices.end();
}

nlohmann::json groupBlockToJson(const GroupBlock& block)
{
    return {
        {"kind", block.kind == GroupKind::eChannel ? kGroupKindChannel : kGroupKindGroup},
        {"members", block.members},
        {"write", block.write},
        {"admin", block.admin},
        {"at", block.at},
    };
}

GroupBlock groupBlockFromJson(const nlohmann::json& body)
{
    GroupBlock block;
    const std::string kind = body.at("kind").get<std::string>();
    if (kind == kGroupKindChannel) {
        block.kind = GroupKind::eChannel;
    } else if (kind == kGroupKindGroup) {
        block.kind = GroupKind::eGroup;
    } else {
        throw std::runtime_error("a group block names an unknown kind: " + kind);
    }
    block.members = body.at("members").get<std::int64_t>();
    block.write = body.at("write").get<bool>();
    block.admin = body.at("admin").get<bool>();
    block.at = body.at("at").get<std::int64_t>();
    return block;
}

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

Session::~Session()
{
    if (pairing_) {
        stopPairing();
    }
}
Session::Session(Session&&) noexcept = default;
Session& Session::operator=(Session&&) noexcept = default;

Session Session::create(const fs::path& accountFile, const AccountKind kind,
    const std::string& passphrase, const std::string& name)
{
    auto db = std::make_unique<AccountDb>(accountFile, passphrase);

    Identity identity = Identity::generate();
    db->putText("identity.pem", identity.privatePem());

    Key sealing = Key::generateSealing();
    db->putText("sealing.pem", sealing.privatePem());

    std::optional<Key> presenceKey;
    Bytes presenceDestKeys;
    if (kind == AccountKind::eUser) {
        presenceKey = Key::generateX25519();
        db->putText(kPresenceKeyRow, presenceKey->privatePem());
        presenceDestKeys = generateI2pMaster().privateKeys;
        db->put(kPresenceDestRow, presenceDestKeys);
    }

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
        {"kind", std::string(accountKindName(kind))},
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
    session.kind_ = kind;
    session.presenceKey_ = std::move(presenceKey);
    session.presenceDestKeys_ = std::move(presenceDestKeys);
    if (kind == AccountKind::eUser) {
        session.presenceDest_ = i2pRoutingHost(session.presenceDestKeys_);
    }
    session.client_->setDestinationOwner(session.destinationOwner());
    return session;
}

Session Session::create(const fs::path& accountFile, const AccountKind kind,
    const ServerEndpoint& endpoint, const std::string& passphrase)
{
    Session session = create(accountFile, kind, passphrase);
    session.connectServer(endpoint);
    return session;
}

void Session::connectServer(const ServerEndpoint& endpoint)
{
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

std::string Session::activeFacadeAddress() const
{
    return client_->activeFacadeAddress();
}

std::string Session::gatewayRefusal() const
{
    return client_->gatewayRefusal();
}

std::vector<std::string> Session::facadeAddresses() const
{
    std::vector<std::string> addresses;
    for (const Facade& facade : client_->endpoint().facades) {
        addresses.push_back(facadeAddress(facade));
    }
    return addresses;
}

Session Session::open(const fs::path& accountFile, const std::string& passphrase)
{
    auto db = std::make_unique<AccountDb>(accountFile, passphrase);
    const nlohmann::json meta = nlohmann::json::parse(db->text("meta"));
    ServerEndpoint endpoint;
    const nlohmann::json& endpointJson = meta.at("endpoint");
    endpoint.serverFingerprint = endpointJson.at("serverFingerprint").get<std::string>();
    try {
        for (const nlohmann::json& address : endpointJson.at("facades")) {
            endpoint.facades.push_back(parseFacadeAddress(address.get<std::string>()));
        }
    } catch (const std::exception& error) {
        endpoint.facades.clear();
        bazarish::log::warn(
            "the saved server address is not usable, the account opens without it: {}",
            error.what());
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
            contact.kind = accountKindFromName(entry.at("kind").get<std::string>());
            contact.presenceKeyB64 = entry.at("presenceKeyB64").get<std::string>();
            contact.presenceDest = entry.at("presenceDest").get<std::string>();
            contact.sealingPublicB64 = entry.at("sealingPublicB64").get<std::string>();
            contact.dest = entry.at("dest").get<std::string>();
            contact.servingSealingB64 = entry.at("servingSealingB64").get<std::string>();
            contact.identityClassicalB64 = entry.at("identityClassicalB64").get<std::string>();
            contact.identityPqB64 = entry.at("identityPqB64").get<std::string>();
            contact.sendPass = entry.at("sendPass").get<std::string>();
            contact.issuedToThem = entry.at("issuedToThem").get<bool>();
            contact.displayName = entry.at("displayName").get<std::string>();
            contact.avatarMime = entry.at("avatarMime").get<std::string>();
            contact.avatarSentToPeer = entry.at("avatarSentToPeer").get<bool>();
            contact.notifications = entry.at("notifications").get<bool>();
            contact.allowCalls = entry.at("allowCalls").get<bool>();
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

    BotMenuMarks botMenus;
    if (db->has("bot-menus")) {
        botMenus = BotMenuMarks::fromJson(nlohmann::json::parse(db->text("bot-menus")));
    }

    Session::RoutingFanout fanout;
    if (db->has("routing-fanout")) {
        const nlohmann::json queued = nlohmann::json::parse(db->text("routing-fanout"));
        fanout.contacts = queued.value("contacts", std::vector<std::string>());
        fanout.registry = queued.value("registry", false);
    }

    auto client = std::make_unique<Client>(
        std::move(identity), clientId, endpoint, i2pDirFor(accountFile));
    Session session(accountFile, std::move(client), std::move(sealing), std::move(contacts));
    session.db_ = std::move(db);
    session.blocked_ = std::move(blocked);
    session.botMenus_ = std::move(botMenus);
    session.fanout_ = std::move(fanout);
    session.pendingPassRevokes_ = std::move(pendingRevokes);
    session.acceptCalls_ = meta.value("acceptCalls", true);
    session.sendReceipts_ = meta.value("sendReceipts", true);
    session.showPresence_ = meta.value("showPresence", true);
    session.contactsAskedBy_
        = meta.value("contactsAskedBy", std::vector<std::string>());
    session.cardB64_ = meta.value("card", std::string{});
    for (const nlohmann::json& held : meta.value("aliasNames", nlohmann::json::array())) {
        session.aliasNames_.push_back(
            Session::AliasHolding{held.at("alias").get<std::string>(),
                held.at("notAfter").get<std::int64_t>(), held.at("autoRenew").get<bool>(),
                held.at("bindingWanted").get<bool>(), held.at("bound").get<bool>(),
                held.at("inApp").get<bool>(), held.value("word", std::string())});
    }
    session.aliasCheckAfter_ = meta.value("aliasCheckAfter", std::int64_t{0});
    session.aliasStatusAt_ = meta.value("aliasStatusAt", std::int64_t{0});
    session.aliasDepositCovers_ = meta.value("aliasDepositCovers", true);
    session.aliasPushedDest_ = meta.value("aliasPushedDest", std::string{});
    session.delegationDays_ = meta.value("delegationDays", kDefaultDelegationDays);
    session.deliveryIdSeed_ = meta.at("deliveryIdSeed").get<std::string>();
    session.deliverySecret_ = fromHex(meta.at("deliverySecret").get<std::string>());
    if (!meta.contains("kind")) {
        throw std::runtime_error("this account was created before account kinds and cannot be opened");
    }
    session.kind_ = accountKindFromName(meta.at("kind").get<std::string>());
    if (session.kind_ == AccountKind::eUser) {
        const std::string presencePem = session.db_->text(kPresenceKeyRow);
        session.presenceDestKeys_ = session.db_->get(kPresenceDestRow).value_or(Bytes{});
        if (presencePem.empty() || session.presenceDestKeys_.empty()) {
            throw std::runtime_error("this account has no presence keys and cannot be opened");
        }
        session.presenceKey_ = Key::fromPrivatePem(presencePem);
        session.presenceDest_ = i2pRoutingHost(session.presenceDestKeys_);
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
    if (const std::string sealingPem = session.db_->text(kAddressSealingRow);
        !sealingPem.empty()) {
        session.addressSealing_ = Key::fromPrivatePem(sealingPem);
        session.addressSigning_ = Key::fromPrivatePem(session.db_->text(kAddressSigningRow));
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

AccountKind Session::contactKind(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        throw std::runtime_error("no such contact: " + peerFingerprint);
    }
    return found->second.kind;
}

std::string Session::sealingPublicB64() const
{
    return toBase64(sealingKey_.publicDer());
}

const Key& Session::presenceKey() const
{
    if (!presenceKey_.has_value()) {
        throw std::logic_error("only a user account has a presence key");
    }
    return *presenceKey_;
}

ContactCard Session::cardContent() const
{
    ContactCard card;
    card.kind = kind_;
    card.sealingPublicKeyDer = sealingKey_.publicDer();
    if (kind_ == AccountKind::eUser) {
        card.presenceKeyDer = presenceKey().publicDer();
        card.presenceDest = presenceDest_;
    }
    return card;
}

nlohmann::json Session::bootstrapBlock(const std::string& pass) const
{
    nlohmann::json block = {
        {"kind", std::string(accountKindName(kind_))},
        {"sealing", sealingPublicB64()},
        {"dest", myDest_},
        {"servingKey", myServingKeyB64_},
        {"pass", pass},
    };
    if (kind_ == AccountKind::eUser) {
        block["presenceKey"] = toBase64(presenceKey().publicDer());
        block["presenceDest"] = presenceDest_;
    }
    return block;
}

std::optional<AccountKind> Session::storedKind(
    const fs::path& accountFile, const std::string& passphrase)
{
    const AccountDb db(accountFile, passphrase);
    const nlohmann::json meta = nlohmann::json::parse(db.text("meta"));
    if (!meta.contains("kind")) {
        return std::nullopt;
    }
    return accountKindFromName(meta.at("kind").get<std::string>());
}

void Session::assignHostedKind(const fs::path& accountFile, const AccountKind kind)
{
    if (kind == AccountKind::eUser) {
        throw std::logic_error("a user account gets its kind when it is created");
    }
    AccountDb db(accountFile, std::string{});
    nlohmann::json meta = nlohmann::json::parse(db.text("meta"));
    if (meta.contains("kind")) {
        if (accountKindFromName(meta.at("kind").get<std::string>()) != kind) {
            throw std::runtime_error("this account was created as another kind of account");
        }
        return;
    }
    meta["kind"] = std::string(accountKindName(kind));
    meta.erase("card");
    db.putText("meta", meta.dump(2));
    if (!db.has("contacts")) {
        return;
    }
    nlohmann::json contacts = nlohmann::json::parse(db.text("contacts"));
    for (auto& [contactFp, entry] : contacts.items()) {
        if (!entry.contains("kind")) {
            entry["kind"] = std::string(accountKindName(AccountKind::eUser));
            entry["presenceKeyB64"] = std::string();
            entry["presenceDest"] = std::string();
        }
    }
    db.putText("contacts", contacts.dump());
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
        facades.push_back(facadeAddress(facade));
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
        {"delegationDays", delegationDays_},
        {"encrypted", encrypted_},
        {"avatarMime", avatarMime_},
        {"acceptCalls", acceptCalls_},
        {"sendReceipts", sendReceipts_},
        {"showPresence", showPresence_},
        {"contactsAskedBy", contactsAskedBy_},
        {"aliasNames", aliasNamesToJson()},
        {"aliasCheckAfter", aliasCheckAfter_},
        {"aliasStatusAt", aliasStatusAt_},
        {"aliasDepositCovers", aliasDepositCovers_},
        {"aliasPushedDest", aliasPushedDest_},
        {"kind", std::string(accountKindName(kind_))},
    };
    db_->putText("meta", meta.dump(2));
}

nlohmann::json Session::aliasNamesToJson() const
{
    nlohmann::json held = nlohmann::json::array();
    for (const AliasHolding& holding : aliasNames_) {
        nlohmann::json name = {{"alias", holding.alias}, {"notAfter", holding.notAfter},
            {"autoRenew", holding.autoRenew}, {"bindingWanted", holding.bindingWanted},
            {"bound", holding.bound}, {"inApp", holding.inApp}};
        if (!holding.word.empty()) {
            name["word"] = holding.word;
        }
        held.push_back(std::move(name));
    }
    return held;
}

nlohmann::json Session::contactsToJson() const
{
    nlohmann::json stored = nlohmann::json::object();
    for (const auto& [fingerprint, contact] : contacts_) {
        stored[fingerprint] = {
            {"kind", std::string(accountKindName(contact.kind))},
            {"presenceKeyB64", contact.presenceKeyB64},
            {"presenceDest", contact.presenceDest},
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
    const DestinationInfo serving = servedOrOwnDestination();
    PublishResult result;
    try {
        result = client_->publishCard(cardContent(), serving, currentCardIssuedAt());
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eAccountUnknown) {
            throw;
        }
        reportConnectProgress(60, "Registering with this server");
        client_->registerHere();
        result = client_->publishCard(cardContent(), serving, currentCardIssuedAt());
    }
    reportConnectProgress(70, "Registered; registering this device");
    const bool movedOnCard = storeCard(result);
    client_->registerThisClient();
    registerEveryPass();

    reportConnectProgress(83, "Checking the address your server serves");
    if (!reconcileI2pAddress()) {
        bazarish::log::warn("this server serves an address this device has no keys for");
        return;
    }
    reportConnectProgress(85, "Publishing your own destination");
    bool movedOnRouting = false;
    try {
        movedOnRouting = delegateRouting();
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eAccountPendingApproval) {
            throw;
        }
        approval_.pending = true;
        bazarish::log::info("account awaiting operator approval: no routing published yet");
        return;
    }
    if (movedOnCard || movedOnRouting) {
        announceNewRouting();
    }
}

void Session::registerSelfHosted()
{
    PublishResult result;
    try {
        result = client_->publishCard(cardContent(), {}, currentCardIssuedAt());
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eAccountUnknown) {
            throw;
        }
        client_->registerHere();
        result = client_->publishCard(cardContent(), {}, currentCardIssuedAt());
    }
    storeCard(result);
    client_->registerThisClient();
}

void Session::publishRouting()
{
    if (delegateRouting()) {
        announceNewRouting();
    }
}

bool Session::delegateRouting()
{
    if (!hasI2pDestination()) {
        throw std::runtime_error("no user-owned I2P destination to publish");
    }
    if (cardB64_.empty()) {
        throw std::runtime_error("not registered: nothing to publish routing into");
    }
    const std::int64_t expires = renewI2pTransient(delegationDays_);
    reportConnectProgress(88, "Delegating your destination to the server");
    DestinationInfo serving
        = client_->sendI2pTransient(i2pTransientBase64(), expires, addressKeys());
    serving.servingSealingKeyDer = servingSealingDer();
    reportConnectProgress(92, "Publishing your contact card");
    const bool moved = storeCard(client_->publishCard(cardContent(), serving, currentCardIssuedAt()));
    reportConnectProgress(96, "Syncing your address to your other devices");
    try {
        syncI2pMasterToSelf();
    } catch (const std::exception& error) {
        bazarish::log::info("master not synced to this account's other devices: {}", error.what());
    }
    approval_ = {};
    return moved;
}

bool Session::storeCard(const PublishResult& result)
{
    const std::string servingKey
        = result.servingSealingKeyDer.empty() ? std::string() : toBase64(result.servingSealingKeyDer);
    const bool held = !myDest_.empty() && !myServingKeyB64_.empty();
    const bool moved = held && (result.dest != myDest_ || servingKey != myServingKeyB64_);
    cardB64_ = toBase64(result.cardDer);
    myDest_ = result.dest;
    myServingKeyB64_ = servingKey;
    persistMeta();
    return moved;
}

AddressKeys Session::addressKeys()
{
    ensureAddressKeys();
    return {addressSealing_->privatePem(), addressSigning_->privatePem()};
}

void Session::issueAddressKeys()
{
    addressSealing_ = Key::generateSealing();
    addressSigning_ = Key::generateSigning();
    db_->putText(kAddressSealingRow, addressSealing_->privatePem());
    db_->putText(kAddressSigningRow, addressSigning_->privatePem());
}

void Session::ensureAddressKeys()
{
    if (!addressSealing_.has_value() || !addressSigning_.has_value()) {
        issueAddressKeys();
    }
}

void Session::adoptAddressKeys(const std::string& sealingPem, const std::string& signingPem)
{
    Key sealing = Key::fromPrivatePem(sealingPem);
    Key signing = Key::fromPrivatePem(signingPem);
    if (!sealing.hasKem() || !signing.isA(kClassicalSigningAlgorithm)) {
        throw std::runtime_error("another device sent address keys of the wrong kind");
    }
    addressSealing_ = std::move(sealing);
    addressSigning_ = std::move(signing);
    db_->putText(kAddressSealingRow, addressSealing_->privatePem());
    db_->putText(kAddressSigningRow, addressSigning_->privatePem());
}

Bytes Session::servingSealingDer() const
{
    return addressSealing_->publicDer();
}

void Session::registerEveryPass()
{
    std::vector<Bytes> handles;
    for (const auto& [peerFingerprint, contact] : contacts_) {
        if (!isBlocked(peerFingerprint) && !isSavedChat(peerFingerprint)) {
            handles.push_back(deliveryPassHandle(passIdFor(peerFingerprint)));
        }
    }
    for (std::size_t from = 0; from < handles.size(); from += kMaxPassesPerRequest) {
        const std::size_t to = std::min(handles.size(), from + kMaxPassesPerRequest);
        client_->registerPasses(std::vector<Bytes>(
            handles.begin() + static_cast<std::ptrdiff_t>(from),
            handles.begin() + static_cast<std::ptrdiff_t>(to)));
    }
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
        issueAddressKeys();
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
    issueAddressKeys();
    return i2pAddress_;
}

void Session::replaceI2pMaster(
    const Bytes& privateKeysDat, const std::string& sealingPem, const std::string& signingPem)
{
    const I2pMasterKey master = loadI2pMaster(privateKeysDat);
    adoptAddressKeys(sealingPem, signingPem);
    i2pMaster_ = master.privateKeys;
    i2pAddress_ = master.host;
    persistI2pBlob("i2p-master", i2pMaster_);
    i2pTransient_.clear();
    db_->erase("i2p-transient");
}

void Session::disableI2pDest()
{
    client_->sendI2pTransient(std::string(), 0, {});
    i2pTransient_.clear();
    db_->erase("i2p-transient");
}

bool Session::adoptI2pMasterFromOwnMailbox(const std::string& wantedHost)
{
    try {
        const std::vector<PendingEntry> waiting = client_->listPending();
        std::vector<MailboxItem> held;
        for (std::size_t begin = 0; begin < waiting.size();) {
            const std::size_t end = fetchBatchEnd(waiting, begin);
            std::vector<MailboxItem> batch = fetchMailbox(*client_,
                std::vector<PendingEntry>(waiting.begin() + static_cast<std::ptrdiff_t>(begin),
                    waiting.begin() + static_cast<std::ptrdiff_t>(end)));
            std::move(batch.begin(), batch.end(), std::back_inserter(held));
            begin = end;
        }
        for (const MailboxItem& item : held) {
            const nlohmann::json body = decodedBody(hybrid::unseal(item.blob, sealingKey_));
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
            replaceI2pMaster(master, body.at("addressSealing").get<std::string>(),
                body.at("addressSigning").get<std::string>());
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
    const AddressKeys keys = addressKeys();
    const nlohmann::json inner = envelope("device.i2p-master", toHex(randomBytes(16)), {
        {"i2pMaster", toBase64(i2pMaster_)},
        {"addressSealing", keys.sealingPem},
        {"addressSigning", keys.signingPem},
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
        {"avatar", {{"mime", avatarMime_}, {"data", nlohmann::json::binary(avatar_)}}},
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
        {"avatar", {{"mime", avatarMime_}, {"data", nlohmann::json::binary(avatar_)}}},
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
    if (botMenus_.forget(peerFingerprint)) {
        db_->putText("bot-menus", botMenus_.toJson().dump());
    }
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
        redelegate();
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
    redelegate();
    return true;
}

void Session::redelegate()
{
    // The card names the keys a delegation carries: without keys yet, both are published anew.
    if (!addressSealing_.has_value() || !addressSigning_.has_value()) {
        publishRouting();
        return;
    }
    const std::int64_t expiresUnix = renewI2pTransient(static_cast<int>(delegationDays_));
    client_->sendI2pTransient(i2pTransientBase64(), expiresUnix, addressKeys());
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
        Identity::fromPrivatePem(client_->identity().privatePem()), destinationOwner());
}

Bytes Session::passIdFor(const std::string& peerFingerprint) const
{
    return deliveryPass(deliverySecret_, peerFingerprint);
}

void Session::submitSignedToSelf(
    nlohmann::json inner, const std::string& kind, const bool later) const
{
    if (!deviceSync_) {
        return;
    }
    signAuthorship(inner, client_->identity(), /*withKeys=*/false);
    const Bytes innerBytes = encodedBody(inner);
    const Key ownSealing = Key::fromPublicDer(sealingKey_.publicDer());
    const std::string deliveryId = toHex(randomBytes(16));
    Bytes sealed = hybrid::seal(innerBytes, ownSealing);
    if (later && selfSendSink_) {
        selfSendSink_(deliveryId, std::move(sealed), kind);
        return;
    }
    client_->submitSelf(deliveryId, sealed, kind);
}

void Session::setDeviceSync(const bool enabled)
{
    deviceSync_ = enabled;
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
    OutboundLeases* const leases = outbound_->leases.get();
    const bool oneAddressOnly = kind == kContactDeliveryClass && leases != nullptr;
    if (oneAddressOnly) {
        leases->keepOwn(toDest);
        task.onOutcome = [leases, toDest, report = watch.onOutcome](
                             const OutboundCourier::Outcome& outcome) {
            leases->release(toDest);
            if (report) {
                report(outcome);
            }
        };
    }
    if (!waitForOutcome) {
        courier.submit(std::move(task));
        return false;
    }
    const OutboundCourier::Outcome outcome = courier.deliverNow(task);
    if (oneAddressOnly) {
        leases->release(toDest);
    }
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
        leases.setAddressing(outbound_->addressing);
        outbound_->courier = std::make_unique<OutboundCourier>(
            [&leases](const std::string& toDest, const std::string& peerName) {
                return leases.prepare(toDest, peerName);
            },
            [&leases](const std::string& toDest, const std::chrono::seconds timeout) {
                return leases.openStream(toDest, timeout);
            },
            DeliverySchedule{}, [&leases](const std::string& toDest) { leases.retire(toDest); },
            outbound_->workers);
    }
    return *outbound_->courier;
}

void Session::setOutboundAddressing(const OutboundAddressing addressing)
{
    const std::lock_guard<std::mutex> lock(outbound_->mutex);
    outbound_->addressing = addressing;
    if (outbound_->leases) {
        outbound_->leases->setAddressing(addressing);
    }
}

void Session::setDeliveryWorkers(const std::size_t workers)
{
    const std::lock_guard<std::mutex> lock(outbound_->mutex);
    outbound_->workers = workers;
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
    requestWithInfo(
        toHex(randomBytes(kRequestIdBytes)), descriptor.fingerprint, text, info, descriptor.name);
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

Session::ContactCardResolved Session::resolveContactCard(const ContactFetchContext& context,
    const ContactCardRequest& request, const std::function<void(CardStep)>& onStep)
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
            const AliasQuery alias = parseAliasQuery(request.uriOrAlias);
            onStep(CardStep::eLookingUpAlias);
            const Descriptor descriptor = fetchClient.resolveAlias(alias, context.resolver,
                nowSeconds(), toRegistry, [&onStep]() { onStep(CardStep::eSolvingPuzzle); });
            onStep(CardStep::eFetchingCard);
            out.info = fetchClient.fetchCard(descriptor, transport);
            out.fingerprint = descriptor.fingerprint;
            out.displayName = safeContactName(alias.name);
        } else {
            const Descriptor descriptor = parseDescriptor(request.uriOrAlias);
            onStep(CardStep::eFetchingCard);
            out.info = fetchClient.fetchCard(descriptor, transport);
            out.fingerprint = descriptor.fingerprint;
            out.displayName = safeContactName(descriptor.name);
        }
        out.ok = true;
        bazarish::log::info("contact-add: card resolved off-thread in {} ms", elapsedMs());
    } catch (const AliasUnknown& error) {
        out.error = error.what();
        out.aliasUnknown = true;
        bazarish::log::info("contact-add: no such alias after {} ms", elapsedMs());
    } catch (const std::exception& error) {
        out.error = error.what();
        out.ok = false;
        bazarish::log::warn(
            "contact-add: resolve failed off-thread after {} ms: {}", elapsedMs(), error.what());
    }
    return out;
}

std::string Session::commitContactAdd(
    const ContactCardResolved& resolved, const DeliveryWatch& watch)
{
    noteChosenName(resolved.fingerprint, resolved.displayName);
    recordRequestedContact(
        resolved.fingerprint, resolved.info, resolved.introText, resolved.displayName);
    sendContactRequest(resolved.fingerprint,
        resolved.requestId.empty() ? toHex(randomBytes(kRequestIdBytes)) : resolved.requestId,
        resolved.introText, watch, /*waitForOutcome=*/false);
    return resolved.fingerprint;
}

bool Session::contactAwaitsAnswer(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    return found != contacts_.end() && found->second.issuedToThem
        && found->second.sendPass.empty();
}

void Session::forgetUnansweredContact(const std::string& peerFingerprint)
{
    if (contactAwaitsAnswer(peerFingerprint)) {
        removeContact(peerFingerprint);
    }
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
        add.request.byAlias = entry.at("byAlias").get<bool>();
        add.request.uriOrAlias = entry.at("uriOrAlias").get<std::string>();
        add.request.introText = entry.at("intro").get<std::string>();
        add.request.requestId = entry.at("requestId").get<std::string>();
        pending.push_back(std::move(add));
    }
    return pending;
}

void Session::noteChosenName(const std::string& peerFingerprint, const std::string& name)
{
    if (peerFingerprint.empty() || name.empty()) {
        return;
    }
    nlohmann::json stored = db_->has(kChosenNamesKey)
        ? nlohmann::json::parse(db_->text(kChosenNamesKey))
        : nlohmann::json::object();
    stored[peerFingerprint] = name;
    db_->putText(kChosenNamesKey, stored.dump());
}

std::string Session::chosenName(const std::string& peerFingerprint) const
{
    if (!db_->has(kChosenNamesKey)) {
        return {};
    }
    const nlohmann::json stored = nlohmann::json::parse(db_->text(kChosenNamesKey));
    return stored.value(peerFingerprint, std::string());
}

void Session::forgetChosenName(const std::string& peerFingerprint)
{
    if (!db_->has(kChosenNamesKey)) {
        return;
    }
    nlohmann::json stored = nlohmann::json::parse(db_->text(kChosenNamesKey));
    if (stored.erase(peerFingerprint) > 0) {
        db_->putText(kChosenNamesKey, stored.dump());
    }
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
    const AliasQuery query = parseAliasQuery(alias);
    const Descriptor descriptor
        = client_->resolveAlias(query, resolverCoordinate_, nowSeconds(), heldTransport());
    const ContactInfo info = client_->fetchCard(descriptor, fetchTransport());
    requestWithInfo(
        toHex(randomBytes(kRequestIdBytes)), descriptor.fingerprint, text, info, query.name);
    return descriptor.fingerprint;
}

void Session::requestWithInfo(const std::string& requestId, const std::string& peerFingerprint,
    const std::string& text, const ContactInfo& info, const std::string& displayName)
{
    recordRequestedContact(peerFingerprint, info, text, displayName);
    try {
        sendContactRequest(
            peerFingerprint, requestId, text, DeliveryWatch{}, /*waitForOutcome=*/true);
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eRecipientServerUnreachable) {
            forgetUnansweredContact(peerFingerprint);
        }
        throw;
    }
}

// Recorded before the request leaves: an unconfirmed request may still be answered.
void Session::recordRequestedContact(const std::string& peerFingerprint,
    const ContactInfo& info, const std::string& text, const std::string& displayName)
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
    validateB32I2pHost(info.card.dest);

    Contact& contact = contacts_[peerFingerprint];
    applyPresence(contact, info.card.kind, toBase64(info.card.presenceKeyDer), info.card.presenceDest);
    contact.dest = info.card.dest;
    contact.sealingPublicB64 = toBase64(peerPrekey.publicDer());
    contact.servingSealingB64 = toBase64(peerServingKey.publicDer());
    rememberKeys(contact, IdentityKeys{info.card.identityClassicalDer, info.card.identityPqDer});
    contact.issuedToThem = true;
    if (!displayName.empty()) {
        contact.displayName = safeContactName(displayName);
        forgetChosenName(peerFingerprint);
    }
    persistContacts();
    shareContactWithDevices(peerFingerprint);
}

void Session::shareContactWithDevices(const std::string& peerFingerprint)
{
    nlohmann::json entry = contactBookEntry(peerFingerprint, contacts_.at(peerFingerprint));
    if (encodedBody(entry).size() > kContactBookChunkBytes) {
        entry.erase("avatar");
    }
    try {
        submitSignedToSelf(envelope("device.contact", toHex(randomBytes(16)), {
            {"device", client_->clientId()},
            {"contact", entry},
        }), "device.contact");
    } catch (const std::exception& error) {
        bazarish::log::warn("a new contact did not reach this account's other devices: {}",
            error.what());
    }
}

void Session::sendContactRequest(const std::string& peerFingerprint,
    const std::string& requestId, const std::string& text, const DeliveryWatch& watch,
    const bool waitForOutcome)
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        throw std::runtime_error("no contact to send a request to: " + peerFingerprint);
    }
    const Key peerPrekey = Key::fromPublicDer(fromBase64(found->second.sealingPublicB64));
    const Key peerServingKey = Key::fromPublicDer(fromBase64(found->second.servingSealingB64));
    const std::string peerDest = found->second.dest;

    const std::string replyPass = registerPassFor(peerFingerprint);

    const nlohmann::json payload = envelope("contact.request", requestId, {
        {"text", text},
        {"dn", name_},
        {"bootstrap", bootstrapBlock(replyPass)},
    });
    nlohmann::json request = payload;
    signAuthorship(request, client_->identity(), /*withKeys=*/true);
    const Bytes encrypted = hybrid::seal(encodedBody(request), peerPrekey);
    deliver(peerDest, peerServingKey, "contact", peerFingerprint, {}, encrypted, watch,
        waitForOutcome, requestId);
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

bool Session::sendFile(const std::string& peerFingerprint, const std::string& location,
    const std::string& e2eId, const DeliveryWatch& watch, const std::string& replyTo,
    const bool forwarded)
{
    if (isSavedChat(peerFingerprint)) {
        throw std::runtime_error("a file cannot be kept in Saved messages: its bytes travel"
            " between the two devices in a conversation, so there would be nothing to open"
            " on another device");
    }
    return announceTransfer(
        kTypeFile, peerFingerprint, location, e2eId, watch, replyTo, forwarded);
}

bool Session::sendPicture(const std::string& peerFingerprint, const Bytes& bytes,
    const std::string& name, const std::string& mime, const std::string& e2eId,
    const DeliveryWatch& watch, const std::string& replyTo, const bool forwarded)
{
    if (bytes.empty()) {
        throw std::runtime_error("the picture is empty");
    }

    const std::string id = e2eId.empty() ? toHex(randomBytes(8)) : e2eId;
    putPicture(id, bytes);

    nlohmann::json inner = envelope(kTypeImage, id, {{"image", imageBody(name, mime, bytes)}});
    addReplyAndForward(inner, replyTo, forwarded);
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

    nlohmann::json inner = envelope(kTypeAudio, id, {{"audio", audioBody(durationMs, opus)}});
    addReplyAndForward(inner, replyTo, forwarded);
    return sendContent(peerFingerprint, std::move(inner), watch);
}

void Session::setGroupBlockSource(GroupBlockSource source)
{
    groupBlockSource_ = std::move(source);
}

nlohmann::json Session::relayedEnvelope(const RelayedPost& post) const
{
    nlohmann::json inner;
    if (post.type == kTypeImage) {
        inner = envelope(kTypeImage, post.id,
            {{"image", imageBody(post.mediaName, post.mime, post.media)}});
    } else if (post.type == kTypeAudio) {
        inner = envelope(kTypeAudio, post.id, {{"audio", audioBody(post.durationMs, post.media)}});
    } else if (post.type == "text") {
        inner = envelope("text", post.id, {{"text", post.text}});
    } else {
        throw std::runtime_error("a group relays text, pictures and voice, not " + post.type);
    }
    inner["sentAt"] = post.sentAt;
    if (post.fromHost) {
        inner["fromHost"] = true;
    } else {
        inner["author"] = post.author;
        inner["contactable"] = post.contactable;
    }
    addReplyAndForward(inner, post.replyTo, false);
    return inner;
}

bool Session::relayPost(
    const std::string& peerFingerprint, const RelayedPost& post, const DeliveryWatch& watch)
{
    return sendContent(peerFingerprint, relayedEnvelope(post), watch);
}

bool Session::relayFits(const RelayedPost& post) const
{
    nlohmann::json inner = relayedEnvelope(post);
    inner["group"] = groupBlockToJson(GroupBlock{GroupKind::eChannel,
        std::numeric_limits<std::int64_t>::max(), true, true,
        std::numeric_limits<std::int64_t>::max()});
    signAuthorship(inner, client_->identity(), /*withKeys=*/false);
    return encodedBody(inner).size() <= kMaxMessagePayloadBytes - kSealOverheadAllowance;
}

void Session::sendGroupState(const std::string& peerFingerprint, const DeliveryWatch& watch)
{
    sendContent(peerFingerprint, envelope(kTypeGroupState, toHex(randomBytes(8)), nlohmann::json::object()), watch);
}

void Session::sendGroupReactions(const std::string& peerFingerprint,
    const nlohmann::json& reactions, const DeliveryWatch& watch)
{
    sendContent(peerFingerprint,
        envelope(kTypeGroupReactions, toHex(randomBytes(8)), {{"reactions", reactions}}), watch);
}

bool Session::announceTransfer(const std::string& type, const std::string& peerFingerprint,
    const std::string& location, const std::string& e2eId,
    const DeliveryWatch& watch, const std::string& replyTo, const bool forwarded)
{
    const std::string id = e2eId.empty() ? toHex(randomBytes(8)) : e2eId;
    const std::unique_ptr<FileInput> input = files_->open(location);
    Sha256 hash;
    std::uint64_t size = 0;
    std::array<char, kHashChunkBytes> buffer{};
    for (std::size_t got = input->read(buffer.data(), buffer.size()); got > 0;
        got = input->read(buffer.data(), buffer.size())) {
        hash.update(buffer.data(), got);
        size += got;
    }
    const std::string digest = toHex(hash.digest());
    const std::string name = files_->name(location);
    sentFiles_[id] = SentFile{location, digest, size, peerFingerprint};
    persistSentFiles();

    nlohmann::json inner = envelope(type, id, {
        {"file",
            {
                {"name", name},
                {"size", size},
                {"sha256", digest},
                {"mime", guessMime(pathFromUtf8(name))},
            }},
    });
    addReplyAndForward(inner, replyTo, forwarded);
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

void Session::sendMenu(
    const std::string& peerFingerprint, const BotMenu& menu, const DeliveryWatch& watch)
{
    requireBotMenu(menu);
    nlohmann::json inner = envelope(kTypeBotMenu, toHex(randomBytes(8)), {
        {"menuId", menu.id},
        {"items", botMenuItemsJson(menu.items)},
    });
    sendContent(peerFingerprint, std::move(inner), watch);
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

void Session::sendDelete(const std::string& peerFingerprint, const std::string& refMessageId,
    const DeliveryWatch& watch)
{
    nlohmann::json inner = envelope("delete", toHex(randomBytes(8)), {
        {"ref", refMessageId},
    });
    sendContent(peerFingerprint, std::move(inner), watch);
}

void Session::tellRoutingTo(const std::string& peerFingerprint)
{
    nlohmann::json inner = envelope("contact.routing", toHex(randomBytes(8)),
        {{"routing", {{"dest", myDest_}, {"servingKey", myServingKeyB64_}}}});
    const std::shared_ptr<EchoQueue> queue = echoQueue_;
    DeliveryWatch watch;
    watch.onOutcome
        = [queue, peerFingerprint](const OutboundCourier::Outcome& outcome) {
              const std::lock_guard<std::mutex> lock(queue->mutex);
              queue->routingTold.emplace_back(peerFingerprint, outcome.stored);
          };
    try {
        (void)sendContent(peerFingerprint, std::move(inner), watch, /*waitForOutcome=*/false,
            /*establishOnFirstReply=*/false);
    } catch (const std::exception& error) {
        bazarish::log::warn("routing update not sent to {}: {}",
            bazarish::log::redact(peerFingerprint), error.what());
        const std::lock_guard<std::mutex> lock(queue->mutex);
        queue->routingTold.emplace_back(peerFingerprint, false);
    }
}

void Session::persistRoutingFanout() const
{
    if (fanout_.empty()) {
        db_->erase("routing-fanout");
        return;
    }
    db_->putText("routing-fanout",
        nlohmann::json{{"contacts", fanout_.contacts}, {"registry", fanout_.registry}}.dump());
}

void Session::queueRoutingFanout()
{
    fanout_.contacts.clear();
    for (const auto& [fingerprint, contact] : contacts_) {
        if (!contact.sendPass.empty() && !contact.sealingPublicB64.empty()
            && !contact.servingSealingB64.empty()) {
            fanout_.contacts.push_back(fingerprint);
        }
    }
    fanout_.registry = resolverCoordinate_.configured()
        && std::any_of(aliasNames_.begin(), aliasNames_.end(),
            [](const AliasHolding& holding) { return holding.bindingWanted; });
    registryFanoutAfter_ = 0;
    persistRoutingFanout();
}

void Session::dropFromRoutingFanout(const std::string& peerFingerprint)
{
    const auto queued
        = std::find(fanout_.contacts.begin(), fanout_.contacts.end(), peerFingerprint);
    if (queued == fanout_.contacts.end()) {
        return;
    }
    fanout_.contacts.erase(queued);
    persistRoutingFanout();
}

void Session::retryRoutingTo(const std::string& peerFingerprint)
{
    tellRoutingTo(peerFingerprint);
}

bool Session::tellRegistryWhereWeAre()
{
    try {
        if (aliasUpdatePending() && !pushAliasDescriptor()) {
            return false;
        }
    } catch (const std::exception& error) {
        log::info("the alias registry has not taken the new address yet: {}", error.what());
        return false;
    }
    noteRegistryTold();
    return true;
}

void Session::runRoutingFanout()
{
    for (const std::string& peer : std::vector<std::string>(fanout_.contacts)) {
        tellRoutingTo(peer);
    }
}

void Session::serviceRoutingFanout()
{
    if (!fanout_.registry || nowSeconds() < registryFanoutAfter_) {
        return;
    }
    registryFanoutAfter_ = nowSeconds() + kRegistryFanoutRetrySeconds;
    (void)tellRegistryWhereWeAre();
}

void Session::noteRegistryTold()
{
    if (!fanout_.registry) {
        return;
    }
    fanout_.registry = false;
    persistRoutingFanout();
}

void Session::replaceOwnAddress()
{
    requireSwitchedOn();
    if (cardB64_.empty()) {
        throw std::runtime_error("not registered: there is no address to replace");
    }
    const I2pMasterKey master = generateI2pMaster();
    i2pMaster_ = master.privateKeys;
    i2pAddress_ = master.host;
    persistI2pBlob("i2p-master", i2pMaster_);
    issueAddressKeys();
    const std::int64_t expires = renewI2pTransient(static_cast<int>(delegationDays_));
    DestinationInfo serving
        = client_->sendI2pTransient(i2pTransientBase64(), expires, addressKeys());
    serving.servingSealingKeyDer = servingSealingDer();
    const bool moved = storeCard(client_->publishCard(cardContent(), serving, currentCardIssuedAt()));
    try {
        syncI2pMasterToSelf();
    } catch (const std::exception& error) {
        log::info("this account's other devices were not handed the new address: {}",
            error.what());
    }
    if (moved) {
        announceNewRouting();
    }
}

void Session::announceNewRouting()
{
    queueRoutingFanout();
    runRoutingFanout();
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

void Session::sendChatTimer(const std::string& peerFingerprint, const std::int64_t seconds)
{
    if (!isChatTimerChoice(seconds)) {
        throw std::invalid_argument("not an auto-delete timer a chat can carry");
    }
    nlohmann::json inner
        = envelope(kTypeChatTimer, toHex(randomBytes(8)), {{"seconds", seconds}});
    sendContent(peerFingerprint, std::move(inner));
}

void Session::setFileSource(std::shared_ptr<const FileSource> files)
{
    files_ = std::move(files);
}

void Session::setTransferHandler(TransferEventFn handler)
{
    const std::lock_guard<std::mutex> lock(transfers_->mutex);
    transfers_->onEvent = std::move(handler);
}

void Session::emitTransfer(const std::string& e2eId, const TransferState state,
    const std::uint64_t bytes, const std::uint64_t total, const std::string& error,
    const TransferStage stage, const std::string& peer)
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

void Session::requestFile(const std::string& peerFingerprint, const std::string& e2eId,
    const std::string& announcedSha256, FileTarget target)
{

    const std::string ask = toHex(randomBytes(kTransferAskBytes));
    nlohmann::json inner = envelope("file.request", toHex(randomBytes(8)), {
        {"fileId", e2eId},
        {"ask", ask},
    });
    const std::int64_t answerByMs
        = inner.at("sentAt").get<std::int64_t>() + kFileRequestFreshnessMs;
    {
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        transfers_->pending[e2eId] = PendingTransfer{std::move(target), announcedSha256,
            std::make_shared<std::atomic<bool>>(false), peerFingerprint, ask, answerByMs};
    }
    emitTransfer(e2eId, TransferState::eRequested, 0, 0, {}, TransferStage::eAsking,
        peerFingerprint);
    sendContent(peerFingerprint, std::move(inner));
}

void Session::expireFileRequests(const std::int64_t nowMs)
{
    std::vector<std::pair<std::string, PendingTransfer>> lapsed;
    {
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        for (auto it = transfers_->pending.begin(); it != transfers_->pending.end();) {
            if (it->second.fetching || nowMs <= it->second.answerByMs) {
                ++it;
                continue;
            }
            lapsed.emplace_back(it->first, std::move(it->second));
            it = transfers_->pending.erase(it);
        }
    }
    for (const auto& [fileId, request] : lapsed) {
        emitTransfer(fileId, TransferState::eFailed, 0, 0, "the sender did not answer",
            TransferStage::eNone, request.peer);
        try {
            sendContent(request.peer,
                envelope("file.cancel", toHex(randomBytes(8)),
                    {{"fileId", fileId}, {"ask", request.ask}}));
        } catch (const std::exception& error) {
            bazarish::log::warn("could not withdraw the file request to {}: {}",
                bazarish::log::redact(request.peer), error.what());
        }
    }
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
            fromPeer.empty() ? "you stopped this transfer" : "the transfer was stopped",
            TransferStage::eNone,
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
    stopFacadeLinkFor(destinationOwner());
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
    if (!files_->exists(found->second.path)) {
        nlohmann::json inner = envelope("file.unavailable", toHex(randomBytes(8)), {
            {"fileId", fileId},
        });
        sendContent(peerFingerprint, std::move(inner));
        return;
    }
    const std::string source = found->second.path;
    const std::shared_ptr<const FileSource> files = files_;
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
    std::thread([this, peerFingerprint, fileId, serveId, forAsk, source, files, ciphertextPath,
                    cancel]() {
        try {
            emitTransfer(fileId, TransferState::eRequested, 0, 0, {}, TransferStage::eEncrypting,
                peerFingerprint);
            const PreparedFile prepared = prepareFile(*files->open(source), ciphertextPath);
            emitTransfer(fileId, TransferState::eRequested, 0, 0, {}, TransferStage::eMakingAddress,
                peerFingerprint);
            bazarish::i2p::EndpointConfig config;
            config.privacy = transferPrivacy();
            config.tunnelQuantity = 2;
            config.label = "File upload";
            config.bulk = true;
            config.owner = destinationOwner();
            const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
                = i2pRouter().createEndpoint(config);
            emitTransfer(fileId, TransferState::eRequested, 0, 0, {}, TransferStage::ePublishing,
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
            offer.header = prepared.header;
            offer.key = prepared.key;
            offer.sha256 = prepared.sha256;
            offer.size = prepared.size;
            nlohmann::json inner = envelope("file.offer", toHex(randomBytes(8)), {
                {"offer", fileOfferToJson(offer)},
                {"forAsk", forAsk},
            });
            sendContent(peerFingerprint, std::move(inner));
            emitTransfer(fileId, TransferState::eRequested, 0, 0, {}, TransferStage::eWaiting,
                peerFingerprint);

            const bool served
                = serveFile(*endpoint, ciphertextPath, std::chrono::seconds(kServeWindowSeconds),
                    [this, fileId, peerFingerprint](const std::uint64_t sent,
                        const std::uint64_t total) {
                        emitTransfer(fileId, TransferState::eRunning, sent, total, {},
                            TransferStage::eSending,
                            peerFingerprint);
                    },
                    cancel.get());
            if (!served) {
                throw std::runtime_error(
                    cancel->load() ? "transfer stopped" : "your contact never connected");
            }
            emitTransfer(
                fileId, TransferState::eDone, 0, 0, {}, TransferStage::eNone, peerFingerprint);
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
    FileTarget target;
    std::string announcedSha256;
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
        target = found->second.target;
        announcedSha256 = found->second.announcedSha256;
        cancel = found->second.cancel;
    }

    std::thread([this, offer, target, announcedSha256, cancel, peer]() {
        try {
            emitTransfer(offer.fileId, TransferState::eRequested, 0, 0, {},
                TransferStage::eConnecting, peer);
            fetchFileOverI2p(i2pRouter(), offer, announcedSha256, target, transferPrivacy(),
                [this, &offer, &peer](const std::uint64_t got, const std::uint64_t total) {
                    emitTransfer(
                        offer.fileId, TransferState::eRunning, got, total, {},
                        TransferStage::eReceiving, peer);
                },
                cancel.get(), destinationOwner());
            emitTransfer(offer.fileId, TransferState::eDone, offer.size, offer.size, {},
                TransferStage::eNone, peer);
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
    if (groupBlockSource_) {
        inner["group"] = groupBlockToJson(groupBlockSource_(peerFingerprint));
    }
    if (const std::optional<std::int64_t> menuId = botMenus_.idFor(peerFingerprint);
        menuId && carriesMenuId(inner.value("type", std::string()))) {
        inner["menuId"] = *menuId;
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
    if (contact.sendPass.empty()) {
        throw std::runtime_error("no delivery pass for this contact yet: " + peerFingerprint);
    }
    bool bootstrapIssued = false;
    DeliveryWatch watchWithLog = watch;

    if (establishOnFirstReply && !contact.issuedToThem && !contact.acceptInFlight) {
        inner["bootstrap"] = bootstrapBlock(registerPassFor(peerFingerprint));
        bootstrapIssued = true;
    }

    signAuthorship(inner, client_->identity(), /*withKeys=*/false);
    const Bytes innerBytes = encodedBody(inner);
    const Key peerSealing = Key::fromPublicDer(fromBase64(contact.sealingPublicB64));
    const Bytes payload = hybrid::seal(innerBytes, peerSealing);
    if (payload.size() > kMaxMessagePayloadBytes) {
        throw std::runtime_error("this message is too large to send ("
            + std::to_string(payload.size() / 1024) + " KiB; the limit is "
            + std::to_string(kMaxMessagePayloadBytes / 1024) + " KiB) - send it as a file");
    }
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
        sentFiles_[id] = SentFile{entry.at("path").get<std::string>(),
            entry.value("sha256", std::string()), entry.value("size", std::uint64_t{0}),
            entry.value("peer", std::string())};
    }
}

void Session::persistSentFiles() const
{
    nlohmann::json stored = nlohmann::json::object();
    for (const auto& [id, file] : sentFiles_) {
        stored[id] = {
            {"path", file.path},
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
    flushOwedAcks();
    std::vector<PendingEntry> waiting;
    {
        const log::Slow timed("asking what the mailbox holds", kSlowStretch);
        waiting = client_->listPending();
    }
    if (serverAnswered_) {
        serverAnswered_();
    }
    std::vector<PendingEntry> taking;
    for (const PendingEntry& entry : waiting) {
        if (awaitingAck_.find(entry.id) != awaitingAck_.end()) {
            continue;
        }
        if (maxItems > 0 && taking.size() >= maxItems) {
            break;
        }
        taking.push_back(entry);
    }
    if (taking.empty()) {
        return takeIn({}, autoAckSurfaced);
    }
    std::vector<IncomingMessage> result;
    for (std::size_t begin = 0; begin < taking.size();) {
        const std::size_t end = fetchBatchEnd(taking, begin);
        std::vector<IncomingMessage> taken = takeIn(
            fetchMailbox(*client_,
                std::vector<PendingEntry>(taking.begin() + static_cast<std::ptrdiff_t>(begin),
                    taking.begin() + static_cast<std::ptrdiff_t>(end))),
            autoAckSurfaced);
        std::move(taken.begin(), taken.end(), std::back_inserter(result));
        begin = end;
    }
    return result;
}

std::vector<IncomingMessage> Session::takeIn(
    std::vector<MailboxItem> items, const bool autoAckSurfaced)
{
    std::vector<IncomingMessage> result;
    std::set<std::string> establishedPeers;
    std::set<std::string> reaskedPeers;
    const log::Slow timedItems(
        "taking in " + std::to_string(items.size()) + " mailbox item(s)", kSlowStretch);
    for (MailboxItem& item : items) {
        const PendingEntry& entry = item.entry;
        if (awaitingAck_.find(entry.id) != awaitingAck_.end()) {
            continue;
        }
        const log::Slow timedItem("taking in " + entry.id, kSlowStretch);
        try {
            const Bytes blob = std::move(item.blob);
            const Bytes plain = hybrid::unseal(blob, sealingKey_);
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

            if (body.at("v").get<int>() > kMessageFormatVersion) {
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
                if (peer.displayName.empty()) {
                    const std::string chosen = chosenName(message.fromFingerprint);
                    if (!chosen.empty()) {
                        peer.displayName = safeContactName(chosen);
                        forgetChosenName(message.fromFingerprint);
                    } else if (!dn.empty()) {
                        peer.displayName = safeContactName(dn);
                    }
                }
            }

            if (asking && known && contacts_[message.fromFingerprint].issuedToThem) {
                contacts_[message.fromFingerprint].issuedToThem = false;
                reaskedPeers.insert(message.fromFingerprint);
            }

            if (body.contains("group")) {
                message.group = groupBlockFromJson(body.at("group"));
                message.author = body.value("author", std::string());
                message.contactable = body.value("contactable", false);
                message.fromHost = body.value("fromHost", false);
            }

            if (type == "text" || type == "contact.request") {
                message.contentType = type;
                message.text = body.value("text", std::string());
            } else if (type == kTypeGroupState && message.group) {
                message.contentType = type;
            } else if (type == kTypeGroupReactions && message.group) {
                message.contentType = type;
                message.groupReactionsJson = body.at("reactions").dump();
            } else if (type == kTypeImage) {
                message.contentType = type;
                const nlohmann::json& picture = body.at("image");
                message.attachmentName = picture.value("name", std::string());
                message.attachmentMime = picture.value("mime", std::string());
                message.attachmentSize = picture.value("size", std::uint64_t{0});
                const nlohmann::json::binary_t& data = picture.at("data").get_binary();
                putPicture(message.e2eId, Bytes(data.begin(), data.end()));
            } else if (type == kTypeAudio) {
                message.contentType = type;
                const nlohmann::json& audio = body.at("audio");
                message.attachmentMime = "audio/opus";
                message.attachmentSize = audio.value("size", std::uint64_t{0});
                message.attachmentDurationMs = audio.value("durationMs", std::int64_t{0});
                const nlohmann::json::binary_t& data = audio.at("data").get_binary();
                putVoice(message.e2eId, Bytes(data.begin(), data.end()));
            } else if (type == kTypeFile) {
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
            } else if (type == kTypeBotMenu && !message.sentByUs) {
                const BotMenu menu = botMenuFromJson(body);
                if (!botMenus_.admit(message.fromFingerprint, menu.id, message.sentAt)) {
                    releaseItem(entry.id);
                    continue;
                }
                db_->putText("bot-menus", botMenus_.toJson().dump());
                message.contentType = type;
                message.menuItemsJson = botMenuItemsJson(menu.items).dump();
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
            } else if (type == "device.contact") {
                message.contentType = type;
                if (body.value("device", std::string()) != client_->clientId()
                    && body.contains("contact")) {
                    applyContactBook(nlohmann::json::array({body.at("contact")}));
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
                        const std::string sealingPem
                            = body.at("addressSealing").get<std::string>();
                        const std::string signingPem
                            = body.at("addressSigning").get<std::string>();
                        if (i2pMaster_.empty()) {
                            replaceI2pMaster(master, sealingPem, signingPem);
                        } else if (master == i2pMaster_) {
                            adoptAddressKeys(sealingPem, signingPem);
                        } else {
                            const std::string offered = i2pRoutingHost(master);
                            if (client_->myDestination().dest == offered) {
                                replaceI2pMaster(master, sealingPem, signingPem);
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
                    const nlohmann::json::binary_t& raw = av.at("data").get_binary();
                    const Bytes data(raw.begin(), raw.end());
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
                        const nlohmann::json::binary_t& raw = av.at("data").get_binary();
                        const Bytes data(raw.begin(), raw.end());
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
                    const bool presence = body.value("showPresence", showPresence_);
                    if (accept != acceptCalls_ || receipts != sendReceipts_
                        || presence != showPresence_) {
                        acceptCalls_ = accept;
                        sendReceipts_ = receipts;
                        showPresence_ = presence;
                        persistMeta();
                        if (presence_) {
                            presence_->setShown(showPresence_);
                        }
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
            } else if (type == kTypeChatTimer
                && isChatTimerChoice(body.value("seconds", std::int64_t{-1}))) {
                message.contentType = type;
                message.timerSeconds = body.at("seconds").get<std::int64_t>();
            } else if (type == "contact.accept") {
                message.contentType = type;
            } else if (type == "contact.routing") {
                message.contentType = type;
            } else {
                message.contentType = "unsupported";
                message.rawType = type;
                message.rawBody = nlohmann::json::to_cbor(body);
            }

            if (body.contains("keyboard")) {
                message.keyboardJson = body.at("keyboard").dump();
            }
            if (body.contains("menuId")) {
                message.menuId = botMenuIdFromJson(body.at("menuId"));
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
    flushOwedAcks();
    return result;
}

void Session::ackPending(const std::string& pendingId)
{
    forgetPending(pendingId);
    releasePending({pendingId});
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
    awaitingAck_.insert(pendingId);
    if (!ackSink_) {
        owedAcks_.push_back(pendingId);
        return;
    }
    ackSink_(pendingId);
}

void Session::flushOwedAcks()
{
    if (owedAcks_.empty()) {
        return;
    }
    client_->ack(owedAcks_);
    for (const std::string& pendingId : owedAcks_) {
        awaitingAck_.erase(pendingId);
    }
    owedAcks_.clear();
}

std::vector<Session::MailboxItem> Session::fetchMailbox(
    Client& client, const std::vector<PendingEntry>& batch)
{
    std::vector<std::string> ids;
    ids.reserve(batch.size());
    for (const PendingEntry& entry : batch) {
        ids.push_back(entry.id);
    }
    std::map<std::string, Bytes> served;
    for (FetchedItem& item : client.fetch(ids)) {
        served.emplace(std::move(item.id), std::move(item.blob));
    }
    std::vector<MailboxItem> items;
    for (const PendingEntry& entry : batch) {
        if (const auto found = served.find(entry.id); found != served.end()) {
            items.push_back({entry, std::move(found->second)});
        }
    }
    return items;
}

void Session::forgetPending(const std::string& pendingId)
{
    if (pendingId.empty()) {
        return;
    }
    awaitingAck_.erase(pendingId);
}

void Session::releasePending(const std::vector<std::string>& pendingIds)
{
    if (pendingIds.empty()) {
        return;
    }
    client_->ack(pendingIds);
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
    std::vector<std::pair<std::string, bool>> told;
    {
        const std::lock_guard<std::mutex> lock(echoQueue_->mutex);
        ready.swap(echoQueue_->pending);
        established.swap(echoQueue_->established);
        notEstablished.swap(echoQueue_->notEstablished);
        told.swap(echoQueue_->routingTold);
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
    for (const auto& [peerFingerprint, delivered] : told) {
        if (delivered) {
            dropFromRoutingFanout(peerFingerprint);
        }
        if (routingFanoutSink_) {
            routingFanoutSink_(peerFingerprint, delivered);
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
        {"kind", std::string(accountKindName(contact.kind))},
        {"presenceKey", contact.presenceKeyB64},
        {"presenceDest", contact.presenceDest},
        {"pass", contact.sendPass},
        {"sealing", contact.sealingPublicB64},
        {"dest", contact.dest},
        {"servingKey", contact.servingSealingB64},
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
        fill(contact.displayName, entry.value("name", std::string()));
        fill(contact.identityClassicalB64, entry.value("identityClassical", std::string()));
        fill(contact.identityPqB64, entry.value("identityPq", std::string()));
        if (isNew) {
            applyPresence(contact, accountKindFromName(entry.at("kind").get<std::string>()),
                entry.at("presenceKey").get<std::string>(),
                entry.at("presenceDest").get<std::string>());
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
    config.tunnelQuantity = bazarish::i2p::kCallTunnelQuantity;
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
            call_.stage = CallStage::eNone;
        }
    });
    bazarish::log::info("call media: from {} to {}",
        bazarish::log::redact(call_.dgram->routingHost()),
        bazarish::log::redact(call_.peerMediaDest));
    try {
        call_.media->start();
    } catch (const std::exception&) {
        endCall();
        throw;
    }
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
    call_.answerByMs = 0;
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
    call_.stage = CallStage::ePreparing;
    auto dgram = openCallMediaSession();
    const std::string callId = toHex(randomBytes(8));
    const Bytes mediaKey = randomBytes(kAeadKeyBytes);
    const std::int64_t invitedAt = nowMillis();
    const bool delivered = sendCallSignal(peerFingerprint, "call.invite",
        {
            {"callId", callId},
                    {"dest", dgram->routingHost()},
            {"key", toBase64(mediaKey)},
            {"sentAt", invitedAt},
        });
    call_.state = CallState::eOutgoing;
    call_.callId = callId;
    call_.peerFingerprint = peerFingerprint;
    call_.mediaKey = mediaKey;
    call_.initiator = true;
    call_.muted = false;
    call_.startedAtMs = nowMillis();
    call_.answerByMs = invitedAt + kCallAnswerWindowMs;
    call_.deliveredAtMs = 0;
    call_.dgram = std::move(dgram);
    if (delivered) {
        call_.deliveredAtMs = nowMillis();
        call_.stage = CallStage::eDelivered;
    } else {
        call_.stage = CallStage::eDelivering;
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
    call_.stage = CallStage::eOpening;
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

void Session::setShowPresence(const bool on)
{
    if (showPresence_ == on) {
        return;
    }
    showPresence_ = on;
    persistMeta();
    syncAccountPrefsToSelf();
    if (presence_) {
        presence_->setShown(showPresence_);
    }
}

void Session::startPresence(PresenceSink sink)
{
    if (kind_ != AccountKind::eUser || presence_) {
        return;
    }
    const Identity& identity = client_->identity();
    PresenceAccount account;
    account.fingerprint = fingerprint();
    account.identityPem = identity.privatePem();
    account.sealingPem = sealingKey_.privatePem();
    account.readerKey = presenceKey().rawPrivate();
    account.destKeys = presenceDestKeys_;
    presence_ = std::make_unique<Presence>(std::move(account),
        i2pPresenceNet(i2pDirFor(accountPath_), destinationOwner()), std::move(sink));
    presence_->setShown(showPresence_);
    setPresenceOrder(presenceOrder_);
}

void Session::setPresenceFocused(const bool focused)
{
    if (presence_) {
        presence_->setFocused(focused);
    }
}

void Session::setPresenceOrder(const std::vector<std::string>& chatOrder)
{
    presenceOrder_ = chatOrder;
    if (!presence_) {
        return;
    }
    std::vector<PresenceContact> ordered;
    for (const std::string& peerFingerprint : chatOrder) {
        const auto found = contacts_.find(peerFingerprint);
        if (found == contacts_.end() || isBlocked(peerFingerprint)
            || found->second.kind != AccountKind::eUser || found->second.presenceKeyB64.empty()) {
            continue;
        }
        const Contact& contact = found->second;
        ordered.push_back(PresenceContact{peerFingerprint, fromBase64(contact.sealingPublicB64),
            IdentityKeys{fromBase64(contact.identityClassicalB64), fromBase64(contact.identityPqB64)},
            fromBase64(contact.presenceKeyB64), contact.presenceDest});
    }
    presence_->setContacts(std::move(ordered));
}

void Session::presenceWatch(std::vector<std::string> peerFingerprints)
{
    if (presence_) {
        presence_->watch(std::move(peerFingerprints));
    }
}

void Session::presenceTyped(const std::string& peerFingerprint)
{
    if (presence_) {
        presence_->typed(peerFingerprint);
    }
}

void Session::syncAccountPrefsToSelf()
{
    try {
        sendSelf({
            {"type", "device.account-prefs"},
            {"acceptCalls", acceptCalls_},
            {"sendReceipts", sendReceipts_},
            {"showPresence", showPresence_},
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
        const std::int64_t arrivedAt = nowMillis();
        const std::optional<std::int64_t> answerBy = callAnswerDeadline(sentAt, arrivedAt);
        if (!answerBy) {
            bazarish::log::info("call invite ignored: it came {} ms after it was sent",
                arrivedAt - sentAt);
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
        call_.startedAtMs = arrivedAt;
        call_.answerByMs = *answerBy;
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
            call_.stage = CallStage::eRinging;
        }
        return;
    }

    if (type == "call.taken") {
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
            call_.stage = CallStage::eOpening;
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
    if (nowMillis() <= call_.answerByMs) {
        return;
    }
    if (call_.state == CallState::eOutgoing) {
        const std::string peer = call_.peerFingerprint;
        const std::string callId = call_.callId;
        if (call_.peerRingingAtMs == 0) {
            bazarish::log::warn("call to {}: no device of theirs reported ringing",
                bazarish::log::redact(peer));
        }
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

bool Session::refreshOwnCard()
{
    if (cardB64_.empty()) {
        throw std::runtime_error("not registered: nothing to refresh");
    }
    return storeCard(
        client_->publishCard(cardContent(), servedOrOwnDestination(), currentCardIssuedAt()));
}

DestinationInfo Session::servedOrOwnDestination()
{
    DestinationInfo serving = client_->myDestination();
    if (serving.dest.empty()) {
        serving.dest = ownRoutingHost();
    }
    ensureAddressKeys();
    serving.servingSealingKeyDer = servingSealingDer();
    return serving;
}

std::string Session::contactInviteUri(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        throw std::runtime_error("not a contact");
    }
    if (found->second.dest.empty()) {
        throw std::runtime_error("no address held for this contact");
    }
    Descriptor descriptor;
    descriptor.fingerprint = peerFingerprint;
    descriptor.dest = found->second.dest;
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
    if (myDest_.empty()) {
        throw std::runtime_error("register first: no destination to publish");
    }
    Descriptor descriptor;
    descriptor.fingerprint = fingerprint();
    descriptor.dest = myDest_;
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
        aliasNames_.push_back(AliasHolding{entry.alias, entry.notAfter, entry.autoRenew,
            entry.bindingWanted, entry.bound, entry.inApp, entry.word});
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

    const bool moved = context.pushedDest != context.dest;
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
        over ? over : heldTransport(), nowSeconds());
    adoptAliasStatus(answer.status);
    try {
        relayAliasStatus(answer.recordDer, answer.delegationDer);
    } catch (const std::exception& error) {
        log::info("could not hand the name answer to this account's other devices: {}",
            error.what());
    }
    return true;
}

void Session::setAliasBinding(const std::string& alias, const bool on)
{
    if (!resolverCoordinate_.configured()) {
        throw std::runtime_error("This build has no alias registry configured.");
    }
    const auto held = std::find_if(aliasNames_.begin(), aliasNames_.end(),
        [&alias](const AliasHolding& holding) { return holding.alias == alias; });
    if (held == aliasNames_.end()) {
        throw std::runtime_error("this account does not hold that name");
    }
    AliasMaintenanceRequest asking;
    asking.op = kAliasBindingOp;
    asking.alias = alias;
    asking.flag = on;
    asking.issuedAt = nowSeconds();
    const Bytes request = signAliasMaintenanceRequest(asking, client_->identity());
    const FetchOutcome outcome
        = heldTransport()(resolverCoordinate_.dest, kAliasBindingOp, request);
    if (!outcome.ok) {
        const std::optional<ErrorCode> known = errorCodeFromString(outcome.errorCode);
        throw std::runtime_error(known ? std::string(readable(*known))
                                       : "The alias registry did not answer.");
    }
    held->bindingWanted = on;
    held->bound = false;
    persistMeta();
    if (on) {
        pushAliasDescriptor();
    }
}

void Session::setAliasWord(const std::string& alias, const std::string& word)
{
    if (!resolverCoordinate_.configured()) {
        throw std::runtime_error("This build has no alias registry configured.");
    }
    const auto held = std::find_if(aliasNames_.begin(), aliasNames_.end(),
        [&alias](const AliasHolding& holding) { return holding.alias == alias; });
    if (held == aliasNames_.end()) {
        throw std::runtime_error("this account does not hold that name");
    }
    AliasMaintenanceRequest asking;
    asking.op = kAliasWordOp;
    asking.alias = alias;
    asking.word = normalizeAliasWord(word);
    asking.issuedAt = nowSeconds();
    const Bytes request = signAliasMaintenanceRequest(asking, client_->identity());
    const FetchOutcome outcome = heldTransport()(resolverCoordinate_.dest, kAliasWordOp, request);
    if (!outcome.ok) {
        const std::optional<ErrorCode> known = errorCodeFromString(outcome.errorCode);
        throw std::runtime_error(known ? std::string(readable(*known))
                                       : "The alias registry did not answer.");
    }
    held->word = asking.word;
    persistMeta();
}

bool Session::aliasUpdatePending() const
{
    if (myDest_.empty()) {
        return false;
    }
    const bool moved = aliasPushedDest_ != myDest_;
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
            over ? over : heldTransport(), aliasNames_, nowSeconds())) {
        return false;
    }
    aliasPushedDest_ = myDest_;
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
    context.pushedDest = aliasPushedDest_;
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
            names.push_back(AliasHolding{entry.alias, entry.notAfter, entry.autoRenew,
                entry.bindingWanted, entry.bound, entry.inApp, entry.word});
        }
        const bool canPublish = !context.dest.empty();
        const bool moved = context.pushedDest != context.dest;
        const bool anyNeeded = std::any_of(names.begin(), names.end(),
            [moved](const AliasHolding& holding) {
                return holding.bindingWanted && (moved || !holding.bound);
            });
        if (anyNeeded && canPublish) {
            out.pointed = tellAliasesWhereWeAre(
                context, Identity::fromPrivatePem(context.identityPem), over, names, now);
            if (out.pointed) {
                out.pushedDest = context.dest;
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
        noteAliasesBound();
        persistMeta();
    }
    if (result.ok && !aliasUpdatePending()) {
        noteRegistryTold();
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

void Session::changePassphrase(const std::string& passphrase)
{
    db_->rekey(passphrase);
    encrypted_ = !passphrase.empty();
    persistMeta();
}

Session::PairingOffer Session::startPairing(PairingEventFn onEvent)
{
    const std::string code = newPairCode();
    Bytes bundle = exportAccountBytes(code);
    if (bundle.size() > kMaxPairBundleBytes) {
        throw std::runtime_error("this account takes " + std::to_string(bundle.size())
            + " bytes, and pairing carries at most " + std::to_string(kMaxPairBundleBytes));
    }

    const std::shared_ptr<PairingRegistry> registry = pairing_;
    const auto cancel = std::make_shared<std::atomic<bool>>(false);
    {
        const std::lock_guard<std::mutex> lock(registry->mutex);
        if (registry->cancel) {
            throw std::runtime_error("this account is already waiting for a device");
        }
    }

    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
        = publishPairDest(i2pRouter(), transferPrivacy(), destinationOwner());

    PairingOffer offer;
    offer.code = code;
    offer.uri = encodePairLink(PairLink{endpoint->routingHost(), client_->endpoint().reseeds});
    {
        const std::lock_guard<std::mutex> lock(registry->mutex);
        registry->cancel = cancel;
        registry->endpoint = endpoint;
        registry->onEvent = std::move(onEvent);
    }

    std::thread([registry, cancel, endpoint, bundle = std::move(bundle), code]() {
        const auto say = [&registry, &cancel](const PairingEvent& event) {
            PairingEventFn handler;
            {
                const std::lock_guard<std::mutex> lock(registry->mutex);
                if (registry->cancel != cancel) {
                    return;
                }
                handler = registry->onEvent;
            }
            if (handler) {
                handler(event);
            }
        };
        try {
            PairingEvent publishing;
            publishing.stage = PairingStage::ePublishing;
            say(publishing);
            const auto deadline
                = std::chrono::steady_clock::now() + std::chrono::seconds(kPublishWaitSeconds);
            bool published = false;
            while (!cancel->load()) {
                if (endpoint->waitReady(std::chrono::seconds(kPublishPollSeconds))) {
                    published = true;
                    break;
                }
                if (std::chrono::steady_clock::now() >= deadline) {
                    throw std::runtime_error("could not publish the pairing address");
                }
            }
            if (published) {
                PairingEvent waiting;
                waiting.stage = PairingStage::eWaiting;
                say(waiting);
                const PairProgressFn onProgress
                    = [&say](const std::uint64_t done, const std::uint64_t total) {
                          PairingEvent sending;
                          sending.stage = PairingStage::eSending;
                          sending.done = done;
                          sending.total = total;
                          say(sending);
                      };
                const PairRefusedFn onWrongCode = [&say](const int wrongCodes) {
                    PairingEvent refused;
                    refused.stage = PairingStage::eWrongCode;
                    refused.wrongCodes = wrongCodes;
                    say(refused);
                };
                const PairServeResult result = servePairBundle(
                    *endpoint, bundle, code, onProgress, onWrongCode, *cancel);
                PairingEvent settled;
                settled.wrongCodes = result.wrongCodes;
                if (result.delivered) {
                    settled.stage = PairingStage::eDone;
                    say(settled);
                } else if (result.wrongCodes >= kMaxWrongCodes) {
                    settled.stage = PairingStage::eRefused;
                    say(settled);
                }
            }
        } catch (const std::exception& error) {
            PairingEvent failed;
            failed.stage = PairingStage::eFailed;
            failed.error = error.what();
            say(failed);
        }
        endpoint->stop();
        const std::lock_guard<std::mutex> lock(registry->mutex);
        if (registry->cancel == cancel) {
            registry->cancel.reset();
            registry->endpoint.reset();
            registry->onEvent = nullptr;
        }
    }).detach();

    return offer;
}

void Session::stopPairing()
{
    const std::shared_ptr<PairingRegistry> registry = pairing_;
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
    {
        const std::lock_guard<std::mutex> lock(registry->mutex);
        if (!registry->cancel) {
            return;
        }
        registry->cancel->store(true);
        registry->cancel.reset();
        endpoint = registry->endpoint.lock();
        registry->endpoint.reset();
        registry->onEvent = nullptr;
    }
    if (endpoint) {
        endpoint->stop();
    }
}

Bytes Session::exportAccountBytes(const std::string& password)
{
    const nlohmann::json meta = nlohmann::json::parse(db_->text("meta"));
    nlohmann::json contacts = contactsToJson();

    nlohmann::json avatars = nlohmann::json::object();
    for (const auto& [contactFp, contact] : contacts_) {
        if (!contact.avatar.empty()) {
            avatars[contactFp] = toBase64(contact.avatar);
        }
    }
    nlohmann::json bundle = {
        {"v", kBundleFormatVersion},
        {"identityPem", client_->identity().privatePem()},
        {"sealingPem", sealingKey_.privatePem()},
        {"i2pMaster", toBase64(i2pMaster_)},
        {"addressSealingPem", addressSealing_ ? addressSealing_->privatePem() : std::string()},
        {"addressSigningPem", addressSigning_ ? addressSigning_->privatePem() : std::string()},
        {"meta", meta},
        {"contacts", contacts},
        {"avatar", toBase64(avatar_)},
        {"contactAvatars", avatars},
        {"blocked", nlohmann::json(blocked_)},
    };
    if (kind_ == AccountKind::eUser) {
        bundle["presencePem"] = presenceKey().privatePem();
        bundle["presenceDest"] = toBase64(presenceDestKeys_);
    }
    const std::string text = bundle.dump();
    return cms::sealWithPassword(Bytes(text.begin(), text.end()), password);
}

void Session::exportAccount(const fs::path& outFile, const std::string& password)
{
    const Bytes sealed = exportAccountBytes(password);
    writeFileText(outFile, std::string(sealed.begin(), sealed.end()));
}

AccountKind Session::bundleKind(const Bytes& sealed, const std::string& password)
{
    const Bytes plain = cms::unsealWithPassword(sealed, password);
    const nlohmann::json bundle = readBundle(plain);
    return accountKindFromName(bundle.at("meta").at("kind").get<std::string>());
}

void Session::importAccountBytes(const Bytes& sealed, const fs::path& accountFile,
    const std::string& password, const std::string& atRestPassphrase)
{
    const Bytes plain = cms::unsealWithPassword(sealed, password);
    const nlohmann::json bundle = readBundle(plain);
    const AccountKind kind = accountKindFromName(bundle.at("meta").at("kind").get<std::string>());
    AccountDb db(accountFile, atRestPassphrase);
    const Identity identity = Identity::fromPrivatePem(bundle.at("identityPem").get<std::string>());
    const Key sealing = Key::fromPrivatePem(bundle.at("sealingPem").get<std::string>());
    db.putText("identity.pem", identity.privatePem());
    db.putText("sealing.pem", sealing.privatePem());
    if (kind == AccountKind::eUser) {
        db.putText(kPresenceKeyRow,
            Key::fromPrivatePem(bundle.at("presencePem").get<std::string>()).privatePem());
        db.put(kPresenceDestRow, fromBase64(bundle.at("presenceDest").get<std::string>()));
    }

    nlohmann::json meta = bundle.at("meta");
    meta["encrypted"] = !atRestPassphrase.empty();
    meta["clientId"] = toHex(randomBytes(8));

    db.putText("meta", meta.dump(2));
    db.putText("contacts", bundle.at("contacts").dump());
    db.putText("blocked", bundle.at("blocked").dump());
    if (const Bytes master = fromBase64(bundle.at("i2pMaster").get<std::string>());
        !master.empty()) {
        db.put("i2p-master", master);
    }
    if (const std::string sealingPem = bundle.at("addressSealingPem").get<std::string>();
        !sealingPem.empty()) {
        db.putText(kAddressSealingRow, Key::fromPrivatePem(sealingPem).privatePem());
        db.putText(kAddressSigningRow,
            Key::fromPrivatePem(bundle.at("addressSigningPem").get<std::string>()).privatePem());
    }
    if (const Bytes avatar = fromBase64(bundle.at("avatar").get<std::string>()); !avatar.empty()) {
        db.put("avatar.self", avatar);
    }
    for (const auto& [contactFp, encoded] : bundle.at("contactAvatars").items()) {
        const Bytes avatar = fromBase64(encoded.get<std::string>());
        if (!avatar.empty()) {
            db.put("avatar-" + contactFp, avatar);
        }
    }
}

void Session::importAccount(const fs::path& bundleFile, const fs::path& accountFile,
    const std::string& password, const std::string& atRestPassphrase)
{
    const std::string sealed = readFileText(bundleFile);
    importAccountBytes(Bytes(sealed.begin(), sealed.end()), accountFile, password,
        atRestPassphrase);
}

}  // namespace bazarish::client
