// Bazarish project (c) 2026
#include "Session.hpp"

#include "AccountDb.hpp"

#include "Authorship.hpp"
#include "FederationFetch.hpp"
#include "I2pKeys.hpp"
#include "I2pRouter.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Descriptor.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Portal.hpp>
#include <bazarish/Reactions.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/Tokens.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <set>
#include <stdexcept>
#include <thread>

namespace bazarish::client {

namespace {

// Whitespace only, or nothing at all: not a name a user could pick an account by.
bool isBlank(const std::string& text)
{
    return text.find_first_not_of(" \t\r\n") == std::string::npos;
}

// The two kinds of message that carry a transfer's metadata. They travel
// identically; the type is how the other side knows whether what is coming is a
// file to keep or a picture to show.
const char* const kTypeFile = "file";
const char* const kTypeImage = "image";
const char* const kTypeVoice = "voice";
// What both sides show between accepting a call and the first media packet.
const char* const kCallOpeningStage = "Opening the audio path";
// Length of a delivery id: what one envelope is called on the wire, in bytes
// before hex encoding.
constexpr std::size_t kDeliveryIdBytes = 16;
// How much of one message an address-book answer may fill. Well under the
// protocol's payload limit, because a contact is never split across two of them
// and an avatar can be most of an entry.
constexpr std::size_t kContactBookChunkBytes = 128 * 1024;
// The account's own secret behind those names.
// A contact request names itself with this many random bytes; the name is what
// makes sending the same request again the same delivery.
constexpr std::size_t kRequestIdBytes = 8;
// How much of a fingerprint stands in for a contact with no local name, where
// one has to be named: enough to tell two apart at a glance.
constexpr std::size_t kShortFingerprintChars = 8;
// Where the intents of unfinished adds live in the account database.
constexpr const char* kPendingAddsKey = "pending-contact-adds";

constexpr std::size_t kDeliveryIdSeedBytes = 32;
// The invitation reached the peer's server, and no device has picked it up yet:
// stored is not the same as ringing, and saying "ringing" here was a guess.
const char* const kCallDeliveredStage = "Invitation delivered";
// A device of theirs answered the invitation by showing the call. This is the
// first proof anything of theirs is listening, and where the ringing tone starts.
const char* const kCallAlertingStage = "Their device is ringing";


namespace fs = std::filesystem;

// The embedded router's state directory. One engine serves the whole
// installation, so it does not sit among the accounts it serves: it lives one
// level up, beside the accounts directory.
fs::path i2pDirFor(const fs::path& accountFile)
{
    return accountFile.parent_path().parent_path() / "i2p";
}

// Tokens minted per batch handed to a contact. When a peer's stash of our
// tokens drops to kRefillThreshold, they signal it and we mint another batch
// (see Contacts.md refill) - so a conversation never runs dry.
constexpr int kTokenBatchSize = 64;
constexpr std::size_t kRefillThreshold = 16;

// How long a call rings before it self-resolves: an unanswered outgoing call
// becomes "no answer", an unanswered incoming one "missed" - so a ringing call
// never blocks the UI waiting forever.
// Two different waits, with two different meanings. Until the peer's server has
// taken the invitation there is nobody ringing yet - that is delivery, and it
// travels the federation. Only once it lands does the peer's phone ring.
constexpr std::int64_t kInviteDeliveryTimeoutMs = 120000;
// How long an active call may hear nothing at all before it is over. Media
// carries a keep-alive twice a second, so this is silence, not a pause.
constexpr std::int64_t kMediaSilenceTimeoutMs = 20000;
constexpr std::int64_t kRingTimeoutMs = 60000;

// Inner end-to-end payload format version (see docs Messages.md).
constexpr int kMessageFormatVersion = 1;

// How long an offline transient delegated to the serving server stays valid.
// Kept short so the operator only ever holds a time-boxed capability; the client
// re-issues a fresh one well before it lapses (see refreshI2pTransientIfDue).
constexpr std::int64_t kSecondsPerDay = 24 * 3600;

// Host form of a standard-LeaseSet I2P address (the per-user destination).
constexpr const char* kI2pHostSuffix = ".b32.i2p";


std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

// Unix milliseconds from the client clock. Stamped into every outgoing message's
// sentAt so the recipient can reorder a burst that arrived out of order and show
// each message's own send time (see docs-main Messages.md "Ordering and timestamps").
std::int64_t nowMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Normalizes an alias to the resolver's canonical form: case-insensitive, 1-32
// characters of a-z and 0-9 (api/AliasResolver.md). Throws on an invalid name so
// a malformed query never reaches the resolver.
std::string normalizeAlias(const std::string& alias)
{
    if (alias.empty() || alias.size() > 32) {
        throw std::runtime_error("alias must be 1-32 characters");
    }
    std::string normalized;
    normalized.reserve(alias.size());
    for (const char c : alias) {
        char lower = c;
        if (c >= 'A' && c <= 'Z') {
            lower = static_cast<char>(c - 'A' + 'a');
        }
        const bool valid = (lower >= 'a' && lower <= 'z') || (lower >= '0' && lower <= '9');
        if (!valid) {
            throw std::runtime_error("alias may contain only a-z and 0-9");
        }
        normalized.push_back(lower);
    }
    return normalized;
}

// The protocol cap on an avatar's compressed size. The UI compresses a chosen
// image to a square within this limit before it ever reaches the core.
constexpr std::size_t kAvatarMaxBytes = 500 * 1024;

// Applies a bootstrap block (the peer's sealing prekey, serving destination +
// serving sealing key, and a fresh token batch) carried by a contact request, a
// first reply or a token refill. Orthogonal to the message's content type.
// thisDevice is the client id of the device applying the bootstrap. A token batch
// addressed to another device is left alone: the peer's devices share a mailbox,
// so every one of them sees this message, and taking a batch meant for one of
// them is how two devices come to spend the same one-time token.
// soleDevice: this account has no other device registered, so an unaddressed
// batch has no one to race with and is simply kept.
void applyBootstrap(Contact& contact, const nlohmann::json& bootstrap,
    const std::string& thisDevice, const bool soleDevice)
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
    if (!bootstrap.contains("replyTokens")) {
        return;
    }
    std::vector<std::string> offered;
    for (const nlohmann::json& token : bootstrap.at("replyTokens")) {
        offered.push_back(token.get<std::string>());
    }
    if (offered.empty()) {
        return;
    }
    const std::string forDevice = bootstrap.value("forDevice", std::string());
    if (forDevice.empty() && !soleDevice) {
        // An unaddressed batch: every device of this account sees it, so keeping
        // all of it would leave several devices holding the same one-time tokens
        // and racing to spend them. Take exactly one, at random so two devices
        // rarely pick the same, and spend it on a batch addressed to this device.
        // Kept alongside what this device already holds rather than replacing it:
        // at a first bootstrap there is nothing to replace, and later - when a
        // contact hands out a fresh batch after lifting a block - throwing the
        // stash away would take the ability to write with it.
        const std::size_t pick = static_cast<std::size_t>(randomBytes(1).front()) % offered.size();
        if (std::find(contact.sendTokens.begin(), contact.sendTokens.end(), offered[pick])
            == contact.sendTokens.end()) {
            contact.sendTokens.push_back(offered[pick]);
        }
        contact.needsOwnBatch = true;
        return;
    }
    if (forDevice.empty()) {
        // The only device on this account: nobody to share with, so there is
        // nothing to buy and no round trip to spend on it.
        contact.needsOwnBatch = false;
        for (const std::string& token : offered) {
            if (std::find(contact.sendTokens.begin(), contact.sendTokens.end(), token)
                == contact.sendTokens.end()) {
                contact.sendTokens.push_back(token);
            }
        }
        return;
    }
    if (forDevice != thisDevice) {
        return;  // somebody else's batch: leaving it alone is the whole point
    }
    contact.needsOwnBatch = false;
    for (const std::string& token : offered) {
        // Dedup: a pending item may be re-fetched before it is acked (acks are
        // deferred until the client durably stores the item), so applying the
        // same bootstrap twice must not double the token stash.
        if (std::find(contact.sendTokens.begin(), contact.sendTokens.end(), token)
            == contact.sendTokens.end()) {
            contact.sendTokens.push_back(token);
        }
    }
}

std::string readFileText(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open " + path.string());
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
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


// Builds the JSON wire form of an inline keyboard: an array of rows, each row
// an array of buttons. A button carries its label plus a callback "data" or a
// "command"; empty actions are omitted so the shape stays minimal.
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

// A best-effort MIME guess from the extension. Content type rendering is a
// client concern; the server never sees this.
// How long a sender keeps a one-time destination up for one request. Long enough
// for a slow I2P transfer with reconnects, short enough that an abandoned request
// does not pin tunnels forever.
constexpr int kServeWindowSeconds = 30 * 60;
// How long a file request is worth answering. The requester waits live on the
// other side, so one that arrives from a mailbox after a restart is answered to
// an empty room - and costs a published destination to find that out.
constexpr std::int64_t kFileRequestFreshnessMs = 5 * 60 * 1000;

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


// The sealed message body, as bytes. CBOR rather than JSON text: the format is
// the same document, but binary values travel as themselves. A picture inside a
// JSON message would have to be base64, which is a third more bytes to encrypt,
// to store in a mailbox and to carry over a tunnel, for nothing.
// What a device tells the account's other devices about: everything that changes
// what the conversation looks like, and nothing that does not. A read receipt, a
// call signal, a token errand and a file's handshake are between this device and
// the correspondent.
bool echoesToOwnDevices(const std::string& type)
{
    static const std::set<std::string> kEchoed{
        "text", "image", "voice", "edit", "delete", "reaction", "chat.clear"};
    return kEchoed.find(type) != kEchoed.end();
}

Bytes encodedBody(const nlohmann::json& inner)
{
    return nlohmann::json::to_cbor(inner);
}

nlohmann::json decodedBody(const Bytes& bytes)
{
    return nlohmann::json::from_cbor(bytes);
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
    // The compiled-in resolver coordinate is empty until a developer-run resolver
    // is deployed and baked in. It can be overridden from the environment so a
    // freshly-built test or local resolver is exercised without a rebuild; all
    // three parts must be present or the alias path stays unconfigured.
    if (const char* const root = std::getenv("BAZARISH_RESOLVER_ROOT");
        root != nullptr && root[0] != '\0') {
        const char* const dest = std::getenv("BAZARISH_RESOLVER_DEST");
        const char* const key = std::getenv("BAZARISH_RESOLVER_KEY");
        if (dest != nullptr && dest[0] != '\0' && key != nullptr && key[0] != '\0') {
            resolverCoordinate_ = ResolverCoordinate{root, dest, fromBase64(key)};
        }
    }
}

bazarish::i2p::Router& Session::i2pRouter() const
{
    // The embedded router is process-global (one per process), so share it across
    // all accounts: its state lives beside the accounts directory, so it is
    // reused regardless of which account starts it first. Started lazily on
    // first transport use; client role (notransit).
    const fs::path dataDir = i2pDirFor(accountPath_);
    // On a first-ever start, take the netDb from our own server over the clearnet
    // facade rather than announcing an I2P bootstrap to a public reseed host.
    seedRouterOnce(dataDir, [this]() { return client_->fetchReseed(); });
    return sharedI2pRouter(dataDir);
}

Session::~Session() = default;
Session::Session(Session&&) noexcept = default;
Session& Session::operator=(Session&&) noexcept = default;

Session Session::create(
    const fs::path& accountFile, const std::string& passphrase, const std::string& name)
{
    // The database is the protection: it is keyed with the passphrase (or with
    // the default key when there is none), so what goes inside is stored as it is.
    auto db = std::make_unique<AccountDb>(accountFile, passphrase);

    Identity identity = Identity::generate();
    db->putText("identity.pem", identity.privatePem());

    Key sealing = Key::generateSealing();
    db->putText("sealing.pem", sealing.privatePem());

    const std::string clientId = toHex(randomBytes(8));
    const bool encrypted = !passphrase.empty();
    const std::string fingerprint = identity.fingerprint();

    // A fresh account has no server yet: an empty facade list marks "unconnected".
    const ServerEndpoint endpoint;

    // Names every envelope this account will ever send; see deliveryIdFor. Drawn
    // here and never redrawn - it is carried through backup and restore.
    const std::string deliveryIdSeed = toHex(randomBytes(kDeliveryIdSeedBytes));
    // Every delivery token this account issues is minted under a mask drawn from
    // this and the correspondent's fingerprint, which is what lets the account
    // revoke a correspondent's tokens later. Drawn once, carried through backup
    // and restore, and never sent anywhere but the account's own server, as a
    // mask, when tokens are being revoked.
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
        {"subscriptionCert", ""},
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
    // Rebind the transport to the new server, reusing the identity and client
    // id. The in-memory identity PEM is unencrypted, so this is independent of
    // the at-rest passphrase.
    client_ = std::make_unique<Client>(
        Identity::fromPrivatePem(client_->identity().privatePem()), client_->clientId(), endpoint,
        i2pDirFor(accountPath_));
    // The new transport starts out owning nothing, and an unowned facade link is
    // shared with nobody: every dial then built its own destination, which is how
    // a single account came to hold several "Facade link" addresses.
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
    // Opening the database is the passphrase check: with the wrong key the pages
    // do not decrypt and this throws rather than reading an empty account.
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
            endpoint.reseeds.push_back(parseFacadeUrl(url.get<std::string>()));
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
            contact.sendTokens = entry.at("sendTokens").get<std::vector<std::string>>();
            contact.issuedToThem = entry.at("issuedToThem").get<bool>();
            // Display name and avatar metadata are newer fields: tolerate their
            // absence in accounts written before they existed.
            contact.displayName = entry.value("displayName", std::string());
            contact.avatarMime = entry.value("avatarMime", std::string());
            contact.avatarSentToPeer = entry.value("avatarSentToPeer", false);
            contact.view = entry.value("view", std::string());
            contact.sharingRefused = entry.value("sharingRefused", false);
            contact.requesterDevice = entry.value("requesterDevice", std::string());
            contact.needsOwnBatch = entry.value("needsOwnBatch", false);
            contact.notifications = entry.value("notifications", true);
            contact.allowCalls = entry.value("allowCalls", true);
            contact.reissueTokens = entry.value("reissueTokens", false);
            contacts.emplace(fingerprint, std::move(contact));
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
    session.acceptCalls_ = meta.value("acceptCalls", true);
    session.sendReceipts_ = meta.value("sendReceipts", true);
    // Which devices have already asked the others for the address book. Kept per
    // device id, not as one flag: a device id is drawn fresh on import, so a copy
    // of an account that has asked before still asks for itself.
    session.contactsAskedBy_
        = meta.value("contactsAskedBy", std::vector<std::string>());
    session.cardB64_ = meta.value("card", std::string{});
    session.view_ = meta.value("view", std::string{});
    session.sharingAllowed_ = meta.value("sharingAllowed", true);
    session.delegationDays_ = meta.value("delegationDays", kDefaultDelegationDays);
    // Written once when the account is made and never again: every envelope this
    // account has ever sent is named under it, so a new one would rename messages
    // that already exist elsewhere. It travels in the backup bundle and comes back
    // with it. An account without one was written before it existed and is not
    // read - there is no release to be compatible with.
    session.deliveryIdSeed_ = meta.value("deliveryIdSeed", std::string());
    if (session.deliveryIdSeed_.empty()) {
        throw std::runtime_error(
            "this account was written before delivery ids were seeded and cannot be read;"
            " create it again");
    }
    // The delivery secret is different from the seed above: an account written
    // before tokens were revocable can still be opened, and is given one here.
    // What it issued before this moment was minted at random, so it carries no
    // mark and cannot be revoked - said out loud, because "remove contact" would
    // otherwise quietly leave those tokens working.
    const std::string deliverySecret = meta.value("deliverySecret", std::string());
    if (deliverySecret.empty()) {
        session.deliverySecret_ = randomBytes(kDeliverySecretSize);
        session.persistMeta();
        bazarish::log::warn("this account predates revocable delivery tokens: the ones it"
            " issued before now cannot be revoked, only the ones it issues from here");
    } else {
        session.deliverySecret_ = fromHex(deliverySecret);
    }
    // Our own routing (dest + serving sealing key) lives in the card we signed;
    // recover it for invites and contact bootstraps.
    if (!session.cardB64_.empty()) {
        const ContactCard card = ContactCard::verify(fromBase64(session.cardB64_));
        session.myDest_ = card.dest;
        if (!card.servingSealingKeyDer.empty()) {
            session.myServingKeyB64_ = toBase64(card.servingSealingKeyDer);
            session.client_->setSessionSealingKey(card.servingSealingKeyDer);
        }
    }
    session.encrypted_ = encrypted;
    session.passphrase_ = passphrase;
    // An account is stored under its own name, so the file name is the name of
    // record: a meta that carries none (or a blank one) leaves the account
    // showing nothing at all, and the file beside it knew all along.
    session.name_ = meta.value("name", std::string{});
    if (isBlank(session.name_)) {
        session.name_ = accountFile.stem().string();
        session.persistMeta();
    }
    session.client_->setDestinationOwner(session.destinationOwner());
    session.loadSentFiles();

    // Load the user-owned I2P destination, if this account has one (per-user
    // path).
    const auto loadBlob = [&session](const std::string& name) -> Bytes {
        return session.db_->get(name).value_or(Bytes{});
    };
    session.i2pMaster_ = loadBlob("i2p-master");
    if (!session.i2pMaster_.empty()) {
        session.i2pAddress_ = i2pBase32(session.i2pMaster_);
    }
    session.i2pTransient_ = loadBlob("i2p-transient");

    // Avatars (own + per-contact): the bytes are their own rows, only the mime
    // flags ride in meta/contacts. Load the bytes for whatever has a mime.
    session.avatarMime_ = meta.value("avatarMime", std::string{});
    if (!session.avatarMime_.empty()) {
        session.avatar_ = loadBlob("avatar.self");
        if (session.avatar_.empty()) {
            session.avatarMime_.clear();  // nothing stored: no avatar
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
    // A nameless account is one the user cannot tell from another in the picker,
    // in an invite or on their other devices, so it is refused where it is set
    // rather than repaired everywhere it is read.
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
    // Persist to meta.json (stored in the clear, like the creation label). Future
    // inviteUri() descriptors carry the new name; existing contacts are not told.
    persistMeta();
    // The account's other devices carry the same account and show the same name.
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
    for (const Facade& reseed : endpoint.reseeds) {
        reseeds.push_back(facadeToUrl(reseed));
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
        // Sticky I2P: once this account has reached its server over I2P it keeps
        // refusing clearnet across restarts, unless the user allowed it again.
        {"acceptCalls", acceptCalls_},
        {"sendReceipts", sendReceipts_},
        {"contactsAskedBy", contactsAskedBy_},
    };
    db_->putText("meta", meta.dump(2));
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
            {"sendTokens", contact.sendTokens},
            {"needsOwnBatch", contact.needsOwnBatch},
            {"issuedToThem", contact.issuedToThem},
            {"displayName", contact.displayName},
            {"avatarMime", contact.avatarMime},
            {"avatarSentToPeer", contact.avatarSentToPeer},
            {"view", contact.view},
            {"sharingRefused", contact.sharingRefused},
            {"requesterDevice", contact.requesterDevice},
            {"notifications", contact.notifications},
            {"allowCalls", contact.allowCalls},
            {"reissueTokens", contact.reissueTokens},
        };
    }
    return stored;
}

void Session::persistContacts() const
{
    // Delivery tokens are write capabilities into a peer's mailbox; they live in
    // the account database, which is where the protection is.
    db_->putText("contacts", contactsToJson().dump());
}

PortalInfo Session::serverPortalInfo()
{
    return client_->fetchPortalInfo();
}

void Session::registerAccount()
{
    // Publishing our card is what turns the registration into an account, and it
    // publishes our sealing key as a prekey so contacts can encrypt their very
    // first message to us before any token exchange. A server that asks for no
    // captcha registers us right here, so connecting is the whole flow and there
    // is no page to visit; one that does asks for a portal visit, and says so.
    PublishResult result;
    try {
        result = client_->publishCard(sealingKey_.publicDer(), ownRoutingHost());
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eDeliveryRejected || client_->fetchPortalInfo().captcha) {
            throw;
        }
        reportConnectProgress(60, "Registering with this server");
        client_->registerHere();
        result = client_->publishCard(sealingKey_.publicDer(), ownRoutingHost());
    }
    // Reported here, not on entry: the call above is what brings the transport
    // up, so its own milestones (reseed, router, dial) come first.
    reportConnectProgress(70, "Registered; registering this device");
    storeCard(result);
    client_->registerThisClient();

    // Every account routes through a destination of its own, so mint the master
    // if this account has none. The delegation can only be handed over once the
    // account exists, which is what the call above created - hence the second,
    // routing-carrying card published right after it.
    ensureI2pDestination();
    reportConnectProgress(85, "Publishing your own destination");
    try {
        publishRouting();
    } catch (const ApiError& error) {
        // A moderated server withholds the destination until an operator
        // approves the account. That is the one refusal that is not a failure:
        // the account stands and the routing is published by a later
        // publishRouting() call, once approved.
        if (error.code != ErrorCode::eAccountPendingApproval) {
            throw;
        }
        // The operator's own note comes with the status poll, not with this
        // refusal; mark the wait and keep whatever note is already known.
        approval_.pending = true;
        bazarish::log::info("account awaiting operator approval: no routing published yet");
    }
}

void Session::registerSelfHosted()
{
    // The same first step as any registration: the card is what turns a
    // registration into an account. What follows it there - minting a master and
    // delegating it - has no meaning when the server is this process.
    PublishResult result;
    try {
        result = client_->publishCard(sealingKey_.publicDer(), {});
    } catch (const ApiError& error) {
        if (error.code != ErrorCode::eDeliveryRejected) {
            throw;
        }
        client_->registerHere();
        result = client_->publishCard(sealingKey_.publicDer(), {});
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
    // The transient is a time-boxed capability that lets the server operate our
    // destination. Its term is the only clock the account has: the server keeps
    // serving while it is renewed.
    const std::int64_t expires = nowSeconds() + delegationDays_ * kSecondsPerDay;
    renewI2pTransient(expires);
    reportConnectProgress(88, "Delegating your destination to the server");
    client_->sendI2pTransient(i2pTransientBase64(), expires);
    reportConnectProgress(92, "Publishing your contact card");
    // Re-publish the card, now carrying the routing. The node grants nothing for
    // it - the account already exists.
    storeCard(client_->publishCard(sealingKey_.publicDer(), ownRoutingHost()));
    // Hand the master to this account's other devices so they keep the same
    // address and can re-issue transients. Best effort: our own routing is
    // published either way, and the sync needs it to be.
    reportConnectProgress(96, "Syncing your address to your other devices");
    try {
        syncI2pMasterToSelf();
    } catch (const std::exception& error) {
        bazarish::log::info("master not synced to this account's other devices: {}", error.what());
    }
    // Routing published means the server serves this account: whatever wait it
    // was under is over.
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
    // With a serving key in hand the client can open a session and stop signing
    // every request; without one it keeps signing, which still works.
    client_->setSessionSealingKey(result.servingSealingKeyDer);
    persistMeta();
}

std::string Session::ownRoutingHost() const
{
    return i2pAddress_.empty() ? std::string() : i2pAddress_ + kI2pHostSuffix;
}

void Session::persistSealedBlob(const std::string& name, const Bytes& blob) const
{
    db_->put(name, blob);
}

void Session::persistI2pBlob(const std::string& name, const Bytes& blob) const
{
    // The master is the user's long-term routing identity and the transient is a
    // live delegation key: they sit in the account database like the private-key
    // PEMs, never beside it.
    persistSealedBlob(name, blob);
}

std::string Session::ensureI2pDestination()
{
    if (i2pMaster_.empty()) {
        const I2pMasterKey master = generateI2pMaster();
        i2pMaster_ = master.privateKeys;
        i2pAddress_ = master.base32;
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

void Session::renewI2pTransient(const std::int64_t expiresUnix)
{
    if (i2pMaster_.empty()) {
        throw std::runtime_error("no user-owned I2P destination to delegate");
    }
    i2pTransient_ = issueI2pOfflineKeys(i2pMaster_, expiresUnix);
    persistI2pBlob("i2p-transient", i2pTransient_);
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
    i2pAddress_ = master.base32;
    persistI2pBlob("i2p-master", i2pMaster_);
    return i2pAddress_;
}

void Session::disableI2pDest()
{
    // Revoking is an empty delegation: the server tears the destination down and
    // holds nothing. The master stays in the account, so publishing again later
    // restores the same address.
    client_->sendI2pTransient(std::string(), 0);
    i2pTransient_.clear();
    db_->erase("i2p-transient");
}

void Session::syncI2pMasterToSelf()
{
    if (i2pMaster_.empty() || myDest_.empty() || myServingKeyB64_.empty()) {
        return;  // nothing to sync, or our own routing is not known yet
    }
    const nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "device.i2p-master"},
        {"id", toHex(randomBytes(16))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"i2pMaster", toBase64(i2pMaster_)},
    };
    // Straight into our own mailbox on our own server, which every device of
    // this account polls: the request's signature is the admission check, so
    // there is no destination to dial and no token to spend.
    submitSignedToSelf(inner, "device.i2p-master");
}

void Session::storeOwnAvatar(const Bytes& data, const std::string& mime)
{
    avatar_ = data;
    avatarMime_ = mime;
    // A removed avatar leaves no row behind: an empty blob would still be the
    // shape of what was there.
    if (avatar_.empty()) {
        db_->erase("avatar.self");
    } else {
        persistSealedBlob("avatar.self", avatar_);
    }
    persistMeta();  // record the mime so open() knows to load the blob
}

void Session::storeContactAvatar(
    const std::string& peerFingerprint, const Bytes& data, const std::string& mime)
{
    if (data.size() > kAvatarMaxBytes) {
        return;  // over the protocol cap: drop it rather than store an oversized blob
    }
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        return;  // an avatar from someone who is not a contact: ignore
    }
    found->second.avatar = data;
    found->second.avatarMime = mime;
    // A contact who removed theirs is telling us to drop it, not to keep an
    // empty one.
    if (data.empty()) {
        db_->erase("avatar-" + peerFingerprint);
    } else {
        persistSealedBlob("avatar-" + peerFingerprint, data);
    }
    persistContacts();  // record the mime flag
}

void Session::syncAvatarToSelf()
{
    if (myDest_.empty() || myServingKeyB64_.empty()) {
        return;  // our own routing is not known yet
    }
    const nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "device.avatar"},
        {"id", toHex(randomBytes(16))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"avatar", {{"mime", avatarMime_}, {"data", toBase64(avatar_)}}},
    };
    // Sealed to our own sealing key: only this account's devices can read it.
    submitSignedToSelf(inner, "device.avatar");
}

void Session::syncContactNameToSelf(const std::string& peerFingerprint, const std::string& name)
{
    if (myDest_.empty() || myServingKeyB64_.empty()) {
        return;  // our own routing is not known yet
    }
    const nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "device.contact-name"},
        {"id", toHex(randomBytes(16))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"peer", peerFingerprint},
        {"name", name},
    };
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

void Session::sendSelf(nlohmann::json inner)
{
    inner["v"] = kMessageFormatVersion;
    inner["id"] = toHex(randomBytes(16));
    inner["from"] = fingerprint();
    inner["sentAt"] = nowMillis();
    // Which of our devices sent it: the one that did already has the change, and
    // skips its own echo.
    inner["device"] = client_->clientId();
    const std::string kind = inner.value("type", std::string());
    submitSignedToSelf(inner, kind);
}

void Session::syncChatPinToSelf(const std::string& peerFingerprint, bool pinned)
{
    if (myDest_.empty() || myServingKeyB64_.empty()) {
        return;  // our own routing is not known yet
    }
    // Mirror a pin/unpin to our own other devices (a purely local list ordering, so
    // it rides the same self-addressed device-sync channel as a contact rename).
    sendSelf({
        {"type", "device.chat-pin"},
        {"peer", peerFingerprint},
        {"pinned", pinned},
    });
}

void Session::syncChatClearToSelf(const std::string& peerFingerprint)
{
    // Clearing "only for me" means this account, not this device: the other
    // devices hold the same conversation and are told to drop it too.
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
        return;  // there is nobody to block
    }
    if (blocked == isBlocked(peerFingerprint)) {
        return;
    }
    if (blocked) {
        blocked_.insert(peerFingerprint);
        // Blocking is not only a local filter: what they hold stops working, so
        // their mail stops arriving at all rather than being read and dropped.
        revokeTokensFor(peerFingerprint);
    } else {
        blocked_.erase(peerFingerprint);
        // Blocking took away what they held; unblocking has to give it back, or
        // they are a contact who cannot answer. The batch rides on the next thing
        // written to them - one delivery, not an errand of its own.
        const auto known = contacts_.find(peerFingerprint);
        if (known != contacts_.end()) {
            known->second.reissueTokens = true;
            persistContacts();
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
        return;  // no avatar to share
    }
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        return;
    }
    Contact& contact = found->second;
    // Share only once the dialog is mutually established (issuedToThem: we are the
    // requester, or we accepted their request - never an automatic reply to an
    // un-accepted incoming request) and we can actually reach the peer.
    if (!contact.issuedToThem || contact.avatarSentToPeer || contact.sendTokens.empty()
        || contact.sealingPublicB64.empty() || contact.servingSealingB64.empty()) {
        return;
    }
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "avatar"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"avatar", {{"mime", avatarMime_}, {"data", toBase64(avatar_)}}},
    };
    try {
        sendContent(peerFingerprint, std::move(inner));
        contact.avatarSentToPeer = true;
        persistContacts();
    } catch (const std::exception& error) {
        // Best effort by design: a peer we cannot reach now gets the avatar on a
        // later establishment or avatar update. The spec surfaces no send error
        // for avatar distribution.
        bazarish::log::warn("avatar push to {} failed: {}", peerFingerprint, error.what());
    }
}

void Session::setAvatar(const Bytes& data, const std::string& mime)
{
    if (data.size() > kAvatarMaxBytes) {
        throw std::runtime_error("avatar exceeds the 500 KB protocol limit");
    }
    // Removing an avatar is as much an event as setting one: the contacts
    // holding the old one are told to drop it. Only those - a contact that never
    // received one has nothing to remove, and an empty push would say nothing.
    const bool removal = data.empty();
    std::vector<std::string> tell;
    for (const auto& [contactFp, contact] : contacts_) {
        if (!removal || contact.avatarSentToPeer) {
            tell.push_back(contactFp);
        }
    }
    storeOwnAvatar(data, mime);
    // A changed avatar must reach every established contact: reset the per-contact
    // "already sent" flag, then push to all reachable contacts (best effort).
    for (auto& [contactFp, contact] : contacts_) {
        (void)contactFp;
        contact.avatarSentToPeer = false;
    }
    persistContacts();
    for (const std::string& contactFp : tell) {
        maybeSendAvatarToContact(contactFp, removal);
    }
    // And to the account's other devices.
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
    // The rename is local; mirror it to the account's other devices only.
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
    // What they hold stops working first: after this the removal is local
    // wherever it is applied, and nothing new can arrive from them.
    revokeTokensFor(peerFingerprint);
    try {
        sendSelf({
            {"type", "device.contact-remove"},
            {"peer", peerFingerprint},
        });
    } catch (const std::exception& error) {
        // The other devices keep the contact until they hear it; say so rather
        // than let them look like they disagreed.
        bazarish::log::warn("contact-remove self-sync failed: {}", error.what());
    }
    removeContact(peerFingerprint);
}

void Session::removeContact(const std::string& peerFingerprint)
{
    if (contacts_.erase(peerFingerprint) == 0) {
        return;  // unknown contact
    }
    // Drop the avatar too, so nothing of the contact lingers in the account.
    db_->erase("avatar-" + peerFingerprint);
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
    // Re-issue at once so the new term applies now rather than at the next
    // renewal, which the old term would have scheduled.
    if (hasI2pDestination() && !myDest_.empty()) {
        const std::int64_t expires = nowSeconds() + delegationDays_ * kSecondsPerDay;
        renewI2pTransient(expires);
        client_->sendI2pTransient(i2pTransientBase64(), expires);
    }
    if (announce) {
        syncDelegationTermToSelf();
    }
}

void Session::syncDelegationTermToSelf()
{
    // The term is the account's, not this device's: a device left on a longer
    // term would keep renewing past what another device chose, and the shorter
    // choice would never take effect (a device stands down while the server
    // holds a delegation comfortably in date).
    const nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "device.delegation-term"},
        {"id", toHex(randomBytes(16))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"device", client_->clientId()},
        {"days", delegationDays_},
    };
    submitSignedToSelf(inner, "device.delegation-term");
}

bool Session::refreshI2pTransientIfDue(const std::int64_t now, const std::int64_t leadSeconds)
{
    if (!hasI2pDestination()) {
        return false;
    }
    const I2pDestStatus status = i2pDestStatus();
    if (!status.approved()) {
        return false;  // no account here, or not approved yet: no destination to keep alive
    }
    // Poll-before-issue: the status read above is the check. If the server still
    // holds a transient comfortably in date, another of the user's devices has
    // already renewed it, so this device stands down.
    if (status.transientExpires != 0 && status.transientExpires - now > leadSeconds) {
        return false;
    }
    const std::int64_t expiresUnix = now + delegationDays_ * kSecondsPerDay;
    renewI2pTransient(expiresUnix);
    client_->sendI2pTransient(i2pTransientBase64(), expiresUnix);
    return true;
}

void Session::noteWire(
    const bool outgoing, std::string what, std::string status, std::string detail) const
{
    client_->wireLog().record(
        {0, outgoing, std::move(what), std::move(status), std::move(detail)});
}

// How a correspondent is named in the connection log: the name this account gave
// them when there is one, and the head of their fingerprint either way - two
// contacts with the same name are still two contacts.
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
    // Fail closed. A challenge that will not say who consumes the signature is
    // not signed at all: the user would have nothing on screen to compare with
    // the site they think they are signing in to, which is exactly how a
    // handshake is stolen.
    const service::LoginConsumer consumer = service::readLoginConsumer(challenge);
    log::info("signing a login for \"{}\" at {} as {}", consumer.name, consumer.place,
        consumer.role);
    return service::signLoginBlob(client_->identity(), nowSeconds(), challenge);
}

Bytes Session::deliveryMaskFor(const std::string& peerFingerprint) const
{
    return deliveryTokenMask(deliverySecret_, peerFingerprint);
}

void Session::submitSignedToSelf(nlohmann::json inner, const std::string& kind) const
{
    // Signed like anything else this account sends: another device of ours reads
    // it as a message from us, and a message from us has to prove it. Our keys
    // do not travel here - the device reading this is us.
    signAuthorship(inner, client_->identity(), /*withKeys=*/false);
    const Bytes innerBytes = encodedBody(inner);
    // Sealed to our own sealing key: only this account's devices can read it.
    const Key ownSealing = Key::fromPublicDer(sealingKey_.publicDer());
    client_->submitSelf(toHex(randomBytes(16)), cms::seal(innerBytes, ownSealing), kind);
}

IdentityKeys Session::knownKeysFor(const std::string& peerFingerprint) const
{
    if (peerFingerprint == fingerprint()) {
        // Our own devices: we are the author, and we hold our own keys.
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
        return;  // learned once; a later message cannot re-introduce a contact
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

std::vector<std::string> Session::issueTokenBatch(const std::string& peerFingerprint)
{
    const Bytes mask = deliveryMaskFor(peerFingerprint);
    std::vector<std::string> tokens;
    std::vector<Bytes> minted;
    tokens.reserve(kTokenBatchSize);
    minted.reserve(kTokenBatchSize);
    for (int i = 0; i < kTokenBatchSize; ++i) {
        const Bytes token = generateDeliveryToken(mask);
        tokens.push_back(toBase64(token));
        minted.push_back(token);
    }
    client_->registerTokens(minted);
    return tokens;
}

std::string Session::issueOneToken(const std::string& peerFingerprint)
{
    const Bytes token = generateDeliveryToken(deliveryMaskFor(peerFingerprint));
    client_->registerTokens({token});
    return toBase64(token);
}

void Session::revokeTokensFor(const std::string& peerFingerprint)
{
    // The mask is all the server needs and all it is given: it drops what was
    // minted under it and learns nothing about whose it was. Best effort - a
    // server we cannot reach right now must not stop the removal, which is local
    // and already done.
    try {
        client_->revokeTokens(deliveryMaskFor(peerFingerprint));
    } catch (const std::exception& error) {
        bazarish::log::warn("tokens for a removed contact were not revoked: {}", error.what());
    }
}

std::string Session::deliveryIdFor(
    const std::string& e2eId, const std::string& mailbox) const
{
    // What one envelope is called on the wire. Derived rather than drawn fresh so
    // that sending the same message again produces the same name and the
    // recipient's server recognises it: a resend after a failure never leaves a
    // second copy in the mailbox, and never spends a second token.
    // Keyed with this account's own secret and bound to the mailbox: the copy that
    // goes to our own devices is named differently from the copy the recipient
    // gets, so the two servers holding them have nothing to match on. Without a
    // message to name - an ack, a receipt of ours - a fresh name is right.
    if (e2eId.empty()) {
        return toHex(randomBytes(kDeliveryIdBytes));
    }
    return bazarish::client::deliveryIdFor(deliveryIdSeed_, e2eId, mailbox);
}

bool Session::deliver(const std::string& toDest, const Key& servingSealingKey,
    const std::string& kind, const std::string& mailbox, const std::optional<Bytes>& token,
    const Bytes& payload, const DeliveryWatch& watch, const bool waitForOutcome,
    const std::string& e2eId)
{
    // The envelope is sealed to the recipient destination's serving sealing key,
    // so the routing metadata is readable only by the server operating that
    // destination.
    const std::string deliveryId = deliveryIdFor(e2eId, mailbox);
    OutboundCourier::Task task;
    task.toDest = toDest;
    // Read here, on the thread that owns the contacts: the status view names an
    // outbound address by the correspondent it carries for. A contact with no
    // local name is still worth telling apart from the others, so it is named by
    // the start of its fingerprint rather than not at all.
    const auto known = contacts_.find(mailbox);
    task.peerName = known != contacts_.end() ? known->second.displayName : std::string();
    if (task.peerName.empty() && !mailbox.empty()) {
        task.peerName = mailbox.substr(0, std::min(mailbox.size(), kShortFingerprintChars));
    }
    task.sealed = sealDeliveryEnvelope(kind, mailbox, deliveryId, token, servingSealingKey);
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
    if (!outcome.stored) {
        // Typed, so a caller can tell a refusal it should repeat (the recipient's
        // address is taking too many contact requests just now) from one it
        // should not.
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
        // Direct over a fresh transient I2P destination, and nothing else. The
        // relay through our own server is gone on purpose: a card fetch names
        // the person being added, and it now travels in the clear (the I2P
        // stream is already encrypted to the destination), so relaying it would
        // hand our own server the one thing this design keeps from it. No
        // router, no fetch - said plainly rather than quietly downgraded.
        if (!i2pEnabled()) {
            throw std::runtime_error("adding a contact needs I2P, and it is switched off");
        }
        bazarish::i2p::Router* const router = sharedI2pRouterIfRunning();
        if (router == nullptr || !router->ready()) {
            throw std::runtime_error(
                "adding a contact needs the I2P router; it is still building tunnels");
        }
        return federationFetchOverI2p(
            *router, toDest, op, sealed, transferPrivacy(), destinationOwner());
    };
}

std::string Session::addByInvite(const std::string& inviteUri, const std::string& text)
{
    // The invite is a descriptor (fingerprint + serving destination + serving
    // sealing key). Fetch the user-signed contact card for that fingerprint and
    // verify it against the fingerprint (api/FederatedResolve.md): a wrong server
    // can only withhold, never forge a card for someone else's fingerprint.
    //
    // ALWAYS over I2P federation, even for a peer on our own server. Do NOT
    // short-circuit to a facade contact lookup for "same-server" peers: when two
    // clients of one server have different i2p destinations, routing the lookup
    // through I2P is what keeps our own server from learning that we and the peer
    // are co-located on it. A facade lookup would disclose that. (Contacts.md /
    // the co-location rule - the by-fingerprint facade path is only for peers a
    // caller already knows are local.)
    const Descriptor descriptor = parseDescriptor(inviteUri);
    const ContactInfo info = client_->fetchCard(descriptor, fetchTransport());
    // Adopt the name advertised in the invite as this contact's local label.
    requestWithInfo(toHex(randomBytes(kRequestIdBytes)), descriptor.fingerprint, text, info,
        descriptor.name, descriptor.view);
    return descriptor.fingerprint;
}

Session::ContactFetchContext Session::contactFetchContext() const
{
    ContactFetchContext ctx;
    ctx.identityPem = client_->identity().privatePem();  // unencrypted in memory
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
    // Its own connection, so the session's transport keeps serving sends and
    // syncs while this one sits waiting - but one connection for the whole loop.
    std::unique_ptr<Client> waiter = std::make_unique<Client>(
        Identity::fromPrivatePem(context.identityPem), context.clientId, context.endpoint,
        context.i2pDataDir);
    waiter->setDestinationOwner(context.destinationOwner);
    if (!context.servingSealingKeyDer.empty()) {
        waiter->setSessionSealingKey(context.servingSealingKeyDer);
    }
    return waiter;
}

bool Session::waitForEvents(Client& waiter, const int waitSeconds)
{
    return !waiter.waitForPending(waitSeconds).empty();
}

Session::ContactCardResolved Session::resolveContactCard(
    const ContactFetchContext& context, const ContactCardRequest& request)
{
    ContactCardResolved out;
    out.introText = request.introText;
    out.requestId = request.requestId;
    // This runs on a background thread (the worker thread stays free for sync), so
    // time it to confirm the connection is never blocked by a slow/unreachable peer.
    const auto started = std::chrono::steady_clock::now();
    const auto elapsedMs = [started]() -> long long {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started)
            .count();
    };
    bazarish::log::info(
        "contact-add: resolving card off-thread (byUsername={})...", request.byUsername);
    try {
        // A private throwaway client with its OWN connection (and its own request
        // mutex), so this slow federated fetch never contends with the session's
        // sync transport. Constructing a Client does no network work.
        Client fetchClient(Identity::fromPrivatePem(context.identityPem), context.clientId,
            context.endpoint, context.i2pDataDir);
        // Mirrors Session::fetchTransport, and like it goes direct or not at
        // all: a lookup relayed through our own server would tell it who is
        // being added.
        const FetchTransport transport = [&context](const std::string& toDest,
                                             const std::string& op,
                                             const Bytes& sealed) -> FetchOutcome {
            if (!context.i2pEnabled) {
                throw std::runtime_error("adding a contact needs I2P, and it is switched off");
            }
            bazarish::i2p::Router* const router = sharedI2pRouterIfRunning();
            if (router == nullptr || !router->ready()) {
                throw std::runtime_error(
                    "adding a contact needs the I2P router; it is still building tunnels");
            }
            return federationFetchOverI2p(
                *router, toDest, op, sealed, context.blobFetchPrivacy, context.destinationOwner);
        };

        if (request.byUsername) {
            const Descriptor descriptor = fetchClient.resolveAlias(
                normalizeAlias(request.uriOrAlias), context.resolver, nowSeconds(), transport);
            out.info = fetchClient.fetchCard(descriptor, transport);
            out.fingerprint = descriptor.fingerprint;
            out.view = descriptor.view;
            // The alias typed becomes the label - unless it claims the saved
            // chat's name, which no contact may carry.
            out.displayName = safeContactName(request.uriOrAlias);
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
    // Fast: register reply tokens, send the request, record the contact. The slow
    // card fetch already happened off-thread in resolveContactCard.
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
        add.request.byUsername = entry.value("byUsername", false);
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
    stored[pending.opId] = {{"byUsername", pending.request.byUsername},
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

std::string Session::aliasBuyArtifacts(const std::string& alias) const
{
    // The artifacts the central resolver's portal needs to claim <alias> for this
    // identity: the normalized name, this user's serving destination + sealing
    // key (its descriptor, mirroring inviteUri), and a user-signed alias
    // certificate binding the name to the identity. The portal buy is driven by
    // POSTing this JSON to /portal/buy - the signing key never leaves the client,
    // the resolver only verifies the signature against the descriptor fingerprint.
    if (myDest_.empty() || myServingKeyB64_.empty()) {
        // The card can only carry routing once the server operates this account's
        // destination, which happens when the delegation is published - not at
        // subscribe time. Name that, so the caller can offer the fix.
        throw std::runtime_error(
            "your destination is not published yet, so an invite would not be reachable");
    }
    const std::string normalized = normalizeAlias(alias);
    const Bytes aliasCert
        = AliasCertificate::issue(client_->identity(), normalized, nowSeconds(), std::nullopt);
    const nlohmann::json artifacts = {
        {"alias", normalized},
        {"srv", myDest_},
        {"srvKey", myServingKeyB64_},
        {"aliasCert", toBase64(aliasCert)},
    };
    return artifacts.dump();
}

std::string Session::addByUsername(const std::string& alias, const std::string& text)
{
    if (!resolverCoordinate_.configured()) {
        throw std::runtime_error("no alias resolver is configured in this build");
    }
    // Resolve the alias to a descriptor on the central resolver. The resolver's
    // record is self-verifying (signed, chained to the hardcoded root), so even a
    // malicious relay can only withhold, never forge the binding. The
    // alias->fingerprint mapping is the one residual trust of the name path: the
    // resolved fingerprint is returned so the UI can surface it for out-of-band
    // verification. Everything after the mapping - the card fetch and its
    // certificates - is verified end-to-end as usual.
    const std::string normalized = normalizeAlias(alias);
    const Descriptor descriptor
        = client_->resolveAlias(normalized, resolverCoordinate_, nowSeconds(), fetchTransport());
    // Card fetch always over I2P (never a facade contact lookup), to avoid
    // disclosing co-location to our own server (see addByInvite / the co-location
    // rule in Contacts.md).
    const ContactInfo info = client_->fetchCard(descriptor, fetchTransport());
    // The alias the user typed becomes this contact's local display name.
    requestWithInfo(toHex(randomBytes(kRequestIdBytes)), descriptor.fingerprint, text, info,
        alias, descriptor.view);
    return descriptor.fingerprint;
}

void Session::requestWithInfo(const std::string& requestId, const std::string& peerFingerprint,
    const std::string& text, const ContactInfo& info, const std::string& displayName,
    const std::string& descriptorView)
{
    if (info.card.user != peerFingerprint) {
        throw std::runtime_error("contact lookup returned a different user");
    }
    // A contact request is tokenless, so what a stranger may put in a mailbox is
    // capped by the protocol. Hold the greeting to what the cap leaves room for
    // here, where the user can still be told, rather than letting the recipient's
    // server refuse a request they cannot see.
    if (text.size() > kMaxContactGreetingBytes) {
        throw std::runtime_error("the introduction may be at most "
            + std::to_string(kMaxContactGreetingBytes) + " characters");
    }
    const Key peerPrekey = info.card.sealingKey();
    const Key peerServingKey = info.card.servingSealingKey();
    const std::string peerDest = info.card.dest;
    validateB32I2pHost(peerDest);

    // Mint a batch the peer will use to write back to us and hand it over, with
    // our prekey and our routing (dest + serving sealing key), in the bootstrap.
    const std::vector<std::string> replyTokens = issueTokenBatch(peerFingerprint);

    const nlohmann::json payload = {
        {"v", kMessageFormatVersion},
        {"type", "contact.request"},
        // The request names itself, and keeps that name across a resend: the
        // recipient's server derives the delivery from it and recognises the
        // second copy of a request as the first one rather than a new one.
        {"id", requestId},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        // Which of our devices is asking: the peer's reply addresses its token
        // batch to it, so our other devices do not adopt the same one-time
        // tokens and race to spend them. They ask for their own when they need
        // to write (token-request).
        {"device", client_->clientId()},
        {"text", text},
        // Our own self-chosen display name, so the recipient can show a named
        // friend in their contacts from the start - mirroring how we learn their
        // name from their descriptor. A one-time seed label, not a live name push
        // (a later rename of ours is never sent; they control the name they keep).
        {"dn", name_},
        {"bootstrap",
            {
                {"sealing", sealingPublicB64()},
                {"dest", myDest_},
                {"servingKey", myServingKeyB64_},
                {"view", sharedView()},
                {"replyTokens", replyTokens},
            }},
    };
    // E2E-encrypted to the peer's prekey: the first message is confidential.
    // Delivered tokenless under the "contact" admission class.
    nlohmann::json request = payload;
    // With our keys: this is the first thing they ever hear from us, and every
    // message after it is checked against what they keep from here.
    signAuthorship(request, client_->identity(), /*withKeys=*/true);
    const Bytes encrypted = cms::seal(encodedBody(request), peerPrekey);
    deliver(peerDest, peerServingKey, "contact", peerFingerprint, std::nullopt, encrypted,
        DeliveryWatch{}, /*waitForOutcome=*/true, requestId);

    // We now know how to reach the peer; reciprocal tokens arrive with the
    // peer's reply.
    Contact& contact = contacts_[peerFingerprint];
    contact.dest = peerDest;
    contact.sealingPublicB64 = toBase64(peerPrekey.publicDer());
    contact.servingSealingB64 = toBase64(peerServingKey.publicDer());
    // Their card signed itself: those are the keys their messages are checked
    // against from here on, so they are kept rather than the fingerprint alone.
    rememberKeys(contact, IdentityKeys{info.card.identityClassicalDer, info.card.identityPqDer});
    contact.issuedToThem = true;
    contact.view = descriptorView;
    // The name (from an invite or the alias used) is a one-time local label set
    // at add time; it is never re-fetched or transmitted afterwards.
    if (!displayName.empty()) {
        contact.displayName = safeContactName(displayName);
    }
    persistContacts();
}

void Session::acceptContactRequest(const std::string& peerFingerprint)
{
    // Agreeing twice sends the requester a second "accepted your request": the
    // reply carries a fresh id, so nothing downstream can collapse the pair. Once
    // we have replied (issuedToThem), there is nothing left to agree to.
    const auto existing = contacts_.find(peerFingerprint);
    if (existing != contacts_.end() && existing->second.issuedToThem) {
        bazarish::log::info("contact request from {} was already agreed to",
            bazarish::log::redact(peerFingerprint));
        return;
    }
    // Agreeing is simply our first reply to the requester: sendContent attaches our
    // bootstrap (our routing + a reply-token batch) because issuedToThem is still
    // false, which is exactly the descriptor the requester needs to finish the add.
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "contact.accept"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        // Our own display name, so the requester can name us in their contacts too -
        // the reverse direction of the requester's `dn` on the contact request. A
        // one-time seed (only when they hold no name for us yet), so names are
        // symmetric after a first exchange.
        {"dn", name_},
    };
    sendContent(peerFingerprint, std::move(inner));
}

bool Session::sendMessage(const std::string& peerFingerprint, const std::string& text,
    const std::string& e2eId, const DeliveryWatch& watch, const std::string& replyTo,
    const bool forwarded)
{
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "text"},
        {"id", e2eId.empty() ? toHex(randomBytes(8)) : e2eId},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"text", text},
    };
    if (forwarded) {
        // A bare mark: this was passed on rather than written here. It names
        // nobody - not who wrote it, not who passed it on before - and proves
        // nothing about the text it travels with.
        inner["forwarded"] = true;
    }
    if (!replyTo.empty()) {
        inner["replyTo"] = replyTo;
    }
    return sendContent(peerFingerprint, std::move(inner), watch);
}

bool Session::sendFile(const std::string& peerFingerprint, const fs::path& path,
    const std::string& e2eId, const DeliveryWatch& watch, const std::string& replyTo)
{
    // A file is an offer, not bytes in a message: the two sides fetch it from
    // each other. There is nobody to fetch it from on another device of ours, so
    // saving one would keep a name that opens nothing.
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
    // A picture rides inside the message. It is small by construction - the
    // composer shrinks it to well under the protocol's message limit, base64 and
    // envelope included - so there is nothing to gain from announcing it and
    // waiting to be asked: it arrives once, with the message, and it arrives
    // even if this client goes offline the moment after sending.
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot read the picture: " + path.string());
    }
    const Bytes bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (bytes.empty()) {
        throw std::runtime_error("the picture is empty: " + path.string());
    }

    const std::string id = e2eId.empty() ? toHex(randomBytes(8)) : e2eId;
    // The sender's own chat draws it from the same place the recipient will.
    putPicture(id, bytes);

    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", kTypeImage},
        {"id", id},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"image",
            {
                {"name", path.filename().string()},
                {"mime", guessMime(path)},
                {"size", bytes.size()},
                {"data", nlohmann::json::binary(bytes)},
            }},
    };
    if (!replyTo.empty()) {
        inner["replyTo"] = replyTo;
    }
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

    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", kTypeVoice},
        {"id", id},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"voice",
            {
                // Opus at the call format: 48 kHz mono, 20 ms frames, each one
                // length-prefixed. The receiver needs nothing else to play it.
                {"codec", "opus"},
                {"durationMs", durationMs},
                {"size", opus.size()},
                {"data", nlohmann::json::binary(opus)},
            }},
    };
    if (forwarded) {
        inner["forwarded"] = true;
    }
    if (!replyTo.empty()) {
        inner["replyTo"] = replyTo;
    }
    return sendContent(peerFingerprint, std::move(inner), watch);
}

// The message that announces a transfer. Only its type differs between a file
// and a picture: the bytes travel the same way, and what the type decides is
// what the other side does when they arrive.
bool Session::announceTransfer(const std::string& type, const std::string& peerFingerprint,
    const fs::path& path, const std::string& e2eId,
    const DeliveryWatch& watch, const std::string& replyTo)
{
    const std::string id = e2eId.empty() ? toHex(randomBytes(8)) : e2eId;
    // Only metadata travels. The digest is over the plaintext, so the recipient
    // can check that what it finally holds is what was announced, independently
    // of how many transfer attempts it took.
    const std::uint64_t size = fs::file_size(path);
    const std::string digest = toHex(sha256File(path));
    sentFiles_[id] = SentFile{path, digest, size, peerFingerprint};
    persistSentFiles();

    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", type},
        {"id", id},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"file",
            {
                {"name", path.filename().string()},
                {"size", size},
                {"sha256", digest},
                {"mime", guessMime(path)},
            }},
    };
    if (!replyTo.empty()) {
        inner["replyTo"] = replyTo;
    }
    return sendContent(peerFingerprint, std::move(inner), watch);
}

void Session::sendInteractive(const std::string& peerFingerprint, const std::string& text,
    const InlineKeyboard& keyboard, const std::string& e2eId,
    const DeliveryWatch& watch)
{
    // An interactive message is a "text" message that additionally carries an
    // inline keyboard. A recipient that does not understand keyboards still
    // renders the text; the registry stays forward-compatible.
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "text"},
        {"id", e2eId.empty() ? toHex(randomBytes(8)) : e2eId},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"text", text},
        {"keyboard", keyboardToJson(keyboard)},
    };
    sendContent(peerFingerprint, std::move(inner), watch);
}

void Session::sendCommand(const std::string& peerFingerprint, const std::string& command,
    const std::string& args, const std::string& e2eId,
    const DeliveryWatch& watch)
{
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "bot.command"},
        {"id", e2eId.empty() ? toHex(randomBytes(8)) : e2eId},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"command", command},
        {"args", args},
    };
    sendContent(peerFingerprint, std::move(inner), watch);
}

void Session::sendCallback(
    const std::string& peerFingerprint, const std::string& data, const std::string& refMessageId)
{
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "bot.callback"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"data", data},
        {"ref", refMessageId},
    };
    sendContent(peerFingerprint, std::move(inner));
}

bool Session::sendEdit(const std::string& peerFingerprint, const std::string& refMessageId,
    const std::string& text, const InlineKeyboard& keyboard,
    const DeliveryWatch& watch)
{
    // An edit fully replaces the target's text and keyboard; the keyboard is
    // always carried (an empty array clears it) so the shape is unambiguous.
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "edit"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"ref", refMessageId},
        {"text", text},
        {"keyboard", keyboardToJson(keyboard)},
    };
    return sendContent(peerFingerprint, std::move(inner), watch);
}

void Session::sendDelete(const std::string& peerFingerprint, const std::string& refMessageId)
{
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "delete"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"ref", refMessageId},
    };
    sendContent(peerFingerprint, std::move(inner));
}

void Session::setSharingAllowed(const bool allowed)
{
    if (sharingAllowed_ == allowed) {
        return;
    }
    sharingAllowed_ = allowed;
    persistMeta();
    // Not announced on its own: every message already carries the capability (or
    // the lack of one), and the one place that tells every contact at once is the
    // key rotation - which is where this setting is made.
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
    const Bytes card = ContactCard::issue(
        client_->identity(), myDest_, sealingKey_.publicDer(), prepared.servingSealingKeyDer);
    // The point of no return: before it, the old key still serves and nothing has
    // changed; after it, the old one is refused and the contacts have to be told.
    stage("Putting the new key in force");
    client_->commitServingKey(card);
    cardB64_ = toBase64(card);
    myServingKeyB64_ = toBase64(prepared.servingSealingKeyDer);
    view_ = prepared.view;
    client_->setSessionSealingKey(prepared.servingSealingKeyDer);
    persistMeta();
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
    // A copy of the names: sending writes to contacts_ (tokens are spent), and
    // iterating the map while it is being written to is not a thing to do.
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
        nlohmann::json inner = {
            {"v", kMessageFormatVersion},
            {"type", "contact.routing"},
            {"id", toHex(randomBytes(8))},
            {"from", fingerprint()},
            {"sentAt", nowMillis()},
        };
        try {
            // The routing block rides on every message; this one carries nothing
            // else, so it is a routing update and nothing more.
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
    // A read receipt confirms a read; it must NOT auto-accept an un-accepted contact
    // request. So it is sent with establishOnFirstReply=false: no bootstrap is
    // attached and issuedToThem is not flipped, so the sender's message can turn
    // green (read) while the request stays pending until explicit Agree (or a real
    // reply). Earlier this bailed entirely for un-accepted contacts, which left the
    // sender stuck on "yellow"; sending without the bootstrap fixes that.
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end() || found->second.sendTokens.empty()) {
        return;  // unknown contact, or no token to deliver the receipt with
    }
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "receipt"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"ref", refMessageId},
    };
    sendContent(peerFingerprint, std::move(inner), {}, false,
        /*establishOnFirstReply=*/false);
}

void Session::sendReaction(const std::string& peerFingerprint, const std::string& refMessageId,
    const std::string& emoji)
{
    if (!reactionWithinLimits(emoji)) {
        throw std::runtime_error("a reaction is at most "
            + std::to_string(kMaxReactionChars) + " characters");
    }
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "reaction"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"ref", refMessageId},
        {"text", emoji},
    };
    sendContent(peerFingerprint, std::move(inner));
}

void Session::sendChatClear(const std::string& peerFingerprint)
{
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "chat.clear"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
    };
    sendContent(peerFingerprint, std::move(inner));
}

void Session::requestTokens(const std::string& peerFingerprint)
{
    // The fields the low-stash flag rides on are read before a type is looked at,
    // so this needs no more than a type the far side consumes without showing.
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "token.request"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"lowStash", true},
        {"device", client_->clientId()},
        {"refillToken", issueOneToken(peerFingerprint)},
    };
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

    {
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        transfers_->pending[e2eId]
            = PendingTransfer{dest, std::make_shared<std::atomic<bool>>(false)};
    }
    emitTransfer(e2eId, TransferState::eRequested, 0, 0, {}, "Asking the sender",
        peerFingerprint);
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "file.request"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"fileId", e2eId},
        // Which of our devices is waiting. Their devices all see the answer, and
        // the one-time address in it belongs to this one; the others leave it and
        // ask for their own copy if they want the file.
        {"device", client_->clientId()},
    };
    sendContent(peerFingerprint, std::move(inner));
}

void Session::cancelTransfer(const std::string& e2eId)
{
    const std::lock_guard<std::mutex> lock(transfers_->mutex);
    const auto found = transfers_->pending.find(e2eId);
    if (found != transfers_->pending.end()) {
        found->second.cancel->store(true);
        transfers_->pending.erase(found);
    }
    // The same id on the other side of a transfer: we are serving this file and
    // the user wants it stopped. The serve loop checks the flag between chunks.
    const auto serving = transfers_->serving.find(e2eId);
    if (serving != transfers_->serving.end()) {
        serving->second->store(true);
        transfers_->serving.erase(serving);
    }
}

void Session::unsend(const std::string& e2eId)
{
    // Nothing was ever copied off this machine, so unsending is just forgetting:
    // a later request is answered "no longer available".
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
    const std::string& forDevice)
{
    const auto found = sentFiles_.find(fileId);
    if (found == sentFiles_.end()) {
        // Another device of ours announced this file and holds the bytes; it will
        // answer. Saying "unavailable" from here would cancel a transfer that is
        // about to work.
        return;
    }
    // The file was announced to one contact. Answering anyone else would mean
    // encrypting a file and publishing a destination for whoever asked - so a
    // request from anybody else is not answered at all, not even with a refusal.
    if (!found->second.peer.empty() && found->second.peer != peerFingerprint) {
        bazarish::log::warn("file request for another contact's file from {}, ignored",
            bazarish::log::redact(peerFingerprint));
        return;
    }
    if (!fs::exists(found->second.path)) {
        // Either we never announced it or the user moved the file: say so instead
        // of leaving the recipient waiting on a transfer that can never start.
        nlohmann::json inner = {
            {"v", kMessageFormatVersion},
            {"type", "file.unavailable"},
            {"id", toHex(randomBytes(8))},
            {"from", fingerprint()},
            {"sentAt", nowMillis()},
            {"fileId", fileId},
        };
        sendContent(peerFingerprint, std::move(inner));
        return;
    }
    const fs::path source = found->second.path;
    // The only thing besides the database that an account ever writes: the sealed
    // copy of a file being served, in a scratch directory beside the accounts. It
    // holds ciphertext under a key that travels in the offer, and it is removed
    // when the transfer window closes.
    const fs::path scratch = accountPath_.parent_path() / ".transfers";
    fs::create_directories(scratch);
    const fs::path ciphertextPath = scratch / ("file-serve-" + toHex(randomBytes(8)) + ".tmp");

    // One serve per asking device: two devices of theirs can pull the same file at
    // once, each over its own one-time address, and each needs its own cancel
    // handle and its own progress.
    const std::string serveId = forDevice.empty() ? fileId : fileId + "@" + forDevice;
    const std::shared_ptr<std::atomic<bool>> cancel = std::make_shared<std::atomic<bool>>(false);
    {
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        transfers_->serving[serveId] = cancel;
    }
    std::thread([this, peerFingerprint, fileId, serveId, forDevice, source, ciphertextPath,
                    cancel]() {
        try {
            // Every stage of one serve is keyed the same way. Reporting the first
            // one under the file id and the rest under the per-device serve id
            // left the sender's row frozen at "Encrypting" while the transfer
            // ran to completion under a key nothing was watching.
            emitTransfer(
                serveId, TransferState::eRequested, 0, 0, {}, "Encrypting", peerFingerprint);
            const PreparedFile prepared = prepareFile(source, ciphertextPath);
            emitTransfer(serveId, TransferState::eRequested, 0, 0, {}, "Making an address",
                peerFingerprint);
            bazarish::i2p::EndpointConfig config{i2pRouter().generateKeys()};
            config.privacy = transferPrivacy();
            config.tunnelQuantity = 2;
            config.label = "File upload";
            config.owner = destinationOwner();
            const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
                = i2pRouter().createEndpoint(config);
            emitTransfer(serveId, TransferState::eRequested, 0, 0, {}, "Publishing the address",
                peerFingerprint);
            if (!endpoint->waitReady(std::chrono::seconds(180))) {
                throw std::runtime_error("could not publish a one-time destination");
            }

            FileOffer offer;
            offer.fileId = fileId;
            offer.host = endpoint->routingHost();
            offer.key = prepared.key;
            offer.sha256 = prepared.sha256;
            offer.size = prepared.size;
            nlohmann::json inner = {
                {"v", kMessageFormatVersion},
                {"type", "file.offer"},
                {"id", toHex(randomBytes(8))},
                {"from", fingerprint()},
                {"sentAt", nowMillis()},
                {"offer", fileOfferToJson(offer)},
                {"forDevice", forDevice},
            };
            sendContent(peerFingerprint, std::move(inner));
            emitTransfer(serveId, TransferState::eRequested, 0, 0, {}, "Waiting for them",
                peerFingerprint);

            const bool served
                = serveFile(*endpoint, ciphertextPath, std::chrono::seconds(kServeWindowSeconds),
                    [this, serveId, peerFingerprint](const std::uint64_t sent,
                        const std::uint64_t total) {
                        emitTransfer(serveId, TransferState::eRunning, sent, total, {}, "Sending",
                            peerFingerprint);
                    },
                    cancel.get());
            // The window closing with nothing served is not a completed transfer.
            // Reporting it as done cleared the bubble as if the file had gone.
            if (!served) {
                throw std::runtime_error(
                    cancel->load() ? "transfer stopped" : "your contact never connected");
            }
            emitTransfer(serveId, TransferState::eDone, 0, 0, {}, {}, peerFingerprint);
            {
                const std::lock_guard<std::mutex> lock(transfers_->mutex);
                transfers_->serving.erase(fileId);
            }
        } catch (const std::exception& error) {
            emitTransfer(
                fileId, TransferState::eFailed, 0, 0, error.what(), {}, peerFingerprint);
            // Tell the other side too: without this the requester waits on an
            // offer that will never come, with nothing to explain the silence.
            try {
                sendContent(peerFingerprint,
                    nlohmann::json{{"v", kMessageFormatVersion}, {"type", "file.unavailable"},
                        {"id", toHex(randomBytes(8))}, {"from", fingerprint()},
                        {"sentAt", nowMillis()}, {"fileId", fileId}});
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
            return;  // an offer for something we never asked for
        }
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
            emitTransfer(offer.fileId, TransferState::eFailed, 0, 0, error.what(), {}, peer);
        }
        const std::lock_guard<std::mutex> lock(transfers_->mutex);
        transfers_->pending.erase(offer.fileId);
    }).detach();
}

bool Session::sendContent(const std::string& peerFingerprint, nlohmann::json inner,
    const DeliveryWatch& watch, bool waitForOutcome, bool establishOnFirstReply,
    const std::string& overrideToken)
{
    // Addressed to ourselves: this is the saved chat, and it is kept rather than
    // delivered. Nothing is dialled, no token is spent, and every device of this
    // account gets it - which is the whole of what saving means here.
    if (isSavedChat(peerFingerprint)) {
        const bool kept = saveToSelf(std::move(inner));
        // Reported like any other send, because the caller is watching for an
        // answer and there is one: the note is on this account's own server, for
        // its other devices to pick up. Left unreported, the interface either
        // waits for a delivery that is not coming or paints one that has not
        // happened yet.
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
    // The other devices of this account see what was done from here. Before the
    // send, so an action that never reaches the contact still reads the same on
    // every device of ours; it goes to our own mailbox and costs no token. Only
    // what changes the conversation travels: a receipt, a call signal or a token
    // errand is this device's business alone.
    if (echoesToOwnDevices(inner.value("type", std::string()))) {
        try {
            echoSentToSelf(peerFingerprint, inner);
        } catch (const std::exception& error) {
            bazarish::log::warn(
                "could not echo what was sent to our own devices: {}", error.what());
        }
    }
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        throw std::runtime_error("unknown contact: " + peerFingerprint);
    }
    Contact& contact = found->second;
    if (contact.sealingPublicB64.empty() || contact.servingSealingB64.empty()) {
        throw std::runtime_error("contact not established yet: " + peerFingerprint);
    }
    // The protocol's ceiling on one message, checked here so the client never
    // builds and encrypts what the recipient's server will refuse. The plaintext
    // is what the limit is about; the envelope around it is small and fixed.
    if (const Bytes body = encodedBody(inner); body.size() > kMaxMessagePayloadBytes) {
        throw std::runtime_error("this message is too large to send ("
            + std::to_string(body.size() / 1024) + " KiB; the limit is "
            + std::to_string(kMaxMessagePayloadBytes / 1024) + " KiB) - send it as a file");
    }
    // A caller-supplied token is spent instead of one from our stash (a prepaid
    // token-refill reply), so an empty stash is not an error on that path.
    const bool useOverrideToken = !overrideToken.empty();
    if (!useOverrideToken && contact.sendTokens.empty()) {
        // This device is out of capacity for them. Ask for a batch of our own -
        // tokenless, so an empty stash can still speak - and tell the user to try
        // again rather than silently dropping what they wrote.
        try {
            sendTokenRequest(peerFingerprint);
        } catch (const std::exception& error) {
            bazarish::log::warn("could not ask {} for delivery tokens: {}",
                bazarish::log::redact(peerFingerprint), error.what());
        }
        // Out of one-time delivery tokens for this peer: their stash refills when
        // they come back online (the low-stash signal we sent earlier prompts it),
        // so this is a recoverable "resend later", not a permanent failure. Surfaced
        // verbatim on the failed bubble, so keep it human and free of the raw
        // fingerprint.
        throw std::runtime_error("Out of delivery tokens for this contact - resend once "
                                 "they are back online and refill your sending capacity.");
    }
    // Captured before the bootstrap block below: when false here, this very send
    // is our first reply to the peer - the moment we accept/establish the dialog.
    const bool wasIssuedToThem = contact.issuedToThem;
    // The caller's watch plus the connection log's own outcome line.
    DeliveryWatch watchWithLog = watch;

    // First reply to a peer that wrote to us first: hand them a bootstrap (our
    // routing + a token batch) so the reverse direction is usable too. A read
    // receipt (establishOnFirstReply=false) skips this, so confirming a read never
    // auto-accepts an un-accepted contact request.
    if (establishOnFirstReply && !contact.issuedToThem) {
        inner["bootstrap"] = {
            {"sealing", sealingPublicB64()},
            {"dest", myDest_},
            {"servingKey", myServingKeyB64_},
            {"view", sharedView()},
            {"replyTokens", issueTokenBatch(peerFingerprint)},
        };
        // Addressed when we know which device asked: their other devices then
        // leave this batch alone and ask for their own rather than spending the
        // same one-time tokens twice.
        if (!contact.requesterDevice.empty()) {
            inner["bootstrap"]["forDevice"] = contact.requesterDevice;
        }
        contact.issuedToThem = true;
        // The batch this carries is a fresh one, so nothing more is owed.
        contact.reissueTokens = false;
    } else if (contact.reissueTokens) {
        // A block was lifted: they hold nothing of ours, so this message carries a
        // batch. Addressed to nobody - any device of theirs may take it, and the
        // rest ask for their own, which is the same rule a refill follows.
        inner["bootstrap"] = {
            {"sealing", sealingPublicB64()},
            {"dest", myDest_},
            {"servingKey", myServingKeyB64_},
            {"view", sharedView()},
            {"replyTokens", issueTokenBatch(peerFingerprint)},
        };
        contact.reissueTokens = false;
    }

    // After spending this token our stash for the peer would be this small; ask
    // them to refill us before it hits zero (Contacts.md), and prepay their reply
    // with one fresh token so the refill is deliverable even if they hold none of
    // ours. Skipped when we spend a caller-supplied token (the refill reply itself).
    if (!useOverrideToken && contact.sendTokens.size() - 1 <= kRefillThreshold) {
        inner["lowStash"] = true;
        inner["device"] = client_->clientId();  // the batch comes back to this device
        inner["refillToken"] = issueOneToken(peerFingerprint);
    }

    // Where to answer us. A destination is not for life: regenerate the key and
    // the address changes, and a contact who learned the old one at introduction
    // would go on dialling it forever. Carrying it on every message means the
    // first thing that arrives after a move repairs the way back.
    // The view capability rides with the routing: it is what lets this contact
    // hand us on to someone else, and without it a dialog that started from
    // their side could never be shared. It grants no more than what they already
    // hold - the card behind it is the dest and keys they are talking to us on.
    inner["routing"]
        = {{"dest", myDest_}, {"servingKey", myServingKeyB64_}, {"view", sharedView()}};

    // Signed last, when the envelope is complete: what the peer verifies is the
    // message as it was actually sent, bootstrap, routing and all. Our keys do
    // not ride here at all: adding a contact goes through their card, so the side
    // that was added already holds the adder's keys from the request, and the
    // adder holds theirs from the card they read.
    signAuthorship(inner, client_->identity(), /*withKeys=*/false);
    const Bytes innerBytes = encodedBody(inner);
    const Key peerSealing = Key::fromPublicDer(fromBase64(contact.sealingPublicB64));
    const Bytes payload = cms::seal(innerBytes, peerSealing);
    const Key peerServingKey = Key::fromPublicDer(fromBase64(contact.servingSealingB64));

    // What this send is, in the connection log: the kind, who it is for and the
    // id the two servers will call it by. The outcome arrives later on a courier
    // thread, so it rides the same callback the interface watches, and it holds
    // the log itself - this account may be closed before the last attempt ends.
    {
        const std::string kind = inner.value("type", std::string("?"));
        const std::string peerLabel = wireName(peerFingerprint);
        const std::string shortId
            = deliveryIdFor(inner.value("id", std::string()), peerFingerprint)
                  .substr(0, kShortFingerprintChars);
        noteWire(true, kind + " to " + peerLabel, "sending", "id " + shortId);
        DeliveryWatch logged = watch;
        const std::shared_ptr<WireLog> log = client_->wireLogHandle();
        logged.onOutcome = [log, kind, peerLabel, shortId, onOutcome = watch.onOutcome](
                               const OutboundCourier::Outcome& outcome) {
            const std::string status = outcome.stored
                ? std::string("stored")
                : "failed" + (outcome.errorCode.empty() ? std::string() : ": " + outcome.errorCode);
            log->record({0, true, kind + " to " + peerLabel, status, "id " + shortId});
            if (onOutcome) {
                onOutcome(outcome);
            }
        };
        watchWithLog = std::move(logged);
    }

    const std::string token = useOverrideToken ? overrideToken : contact.sendTokens.back();
    // Spent before the envelope leaves, not after it lands. A send this client
    // gives up on may still have been stored by the recipient - only its
    // confirmation was lost - and a token that may already have been consumed
    // there must never be offered to a second message, or that message is the one
    // that fails. Resending THIS message is free either way: the delivery id is
    // derived from the message, so the recipient's server recognises the repeat
    // and spends nothing for it.
    // A caller-supplied token is not from our stash, so the stash is left untouched.
    if (!useOverrideToken) {
        contact.sendTokens.pop_back();
        persistContacts();
    }

    // The message's own id goes down with it: the envelope is named after it, so
    // sending this message again is the same delivery rather than a second one.
    const bool delivered = deliver(contact.dest, peerServingKey, "content", peerFingerprint,
        fromBase64(token), payload, watchWithLog, waitForOutcome,
        inner.value("id", std::string()));

    // If this send is the first reply that just established the reverse direction
    // (we accepted their request), share our avatar now - consent-gated, exactly
    // the "reply to the friend request" the spec ties avatar exchange to.
    if (!wasIssuedToThem) {
        maybeSendAvatarToContact(peerFingerprint);
    }
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


std::vector<IncomingMessage> Session::sync(bool autoAckSurfaced)
{
    std::vector<IncomingMessage> result;
    // Peers whose stash of our tokens is running low and who asked for a
    // refill; topped up after the fetch loop so we never write mid-iteration.
    std::set<std::pair<std::string, std::string>> refillPeers;  // peer, device
    // A fresh token each low-stash requester embedded to prepay our refill reply, by
    // peer fingerprint: we spend exactly it to deliver the batch (so the reply lands
    // even when we hold none of their tokens) and never fold it into our stash.
    std::map<std::string, std::string> prepaidRefillTokens;
    // Peers that carried a bootstrap this sync (a contact request, or - for one we
    // requested - their acceptance): we push our avatar to the established ones
    // after the loop, same "never write mid-iteration" rule.
    std::set<std::string> establishedPeers;
    for (const PendingEntry& entry : client_->listPending()) {
        try {
            const Bytes blob = client_->fetchBlob(entry.id);
            // Every item is sealed to our user sealing key the same way; the
            // server-visible delivery class never changes how we decrypt.
            const Bytes plain = cms::unseal(blob, sealingKey_);
            nlohmann::json body = decodedBody(plain);

            // Who wrote it, before anything in it is believed. The envelope
            // carries the answer itself: the transport only proves that someone
            // holding a token of ours put it there, which is admission, not
            // authorship. A message whose signature is missing, broken, or made
            // by a key that is not the sender it claims to be, is consumed here -
            // it never reaches a chat, a contact entry or the user.
            {
                const std::string claimed = body.value("from", std::string());
                std::string author;
                try {
                    // Keys travel only with a bootstrap, so most messages are
                    // checked against what this account already keeps for the
                    // sender they claim to be. A sender it keeps nothing for is
                    // one it cannot check - and does not read.
                    author = authorOf(body, knownKeysFor(claimed));
                } catch (const std::exception& error) {
                    bazarish::log::warn("sync: dropping an item that does not name its "
                                        "author: {}", error.what());
                    noteWire(false, "unsigned item", "dropped", error.what());
                    client_->ack(entry.id);
                    continue;
                }
                if (author != claimed) {
                    bazarish::log::warn("sync: dropping an item signed by {} claiming to be {}",
                        bazarish::log::redact(author), bazarish::log::redact(claimed));
                    noteWire(false, "item signed by another key", "dropped", {});
                    client_->ack(entry.id);
                    continue;
                }
            }

            IncomingMessage message;
            message.deliveryClass = entry.deliveryClass;
            // An echo of what another device of ours sent: unwrap it and let the
            // ordinary dispatch below read it, so a sent file or reply arrives here
            // exactly as it did there. The conversation is the peer it went to, and
            // the device that sent it ignores its own echo.
            if (body.value("type", std::string()) == "device.message"
                && body.value("from", std::string()) == fingerprint()) {
                if (body.value("device", std::string()) == client_->clientId()) {
                    client_->ack(entry.id);
                    continue;
                }
                const std::string peer = body.value("peer", std::string());
                body = body.at("message");
                body["from"] = peer;  // the conversation this belongs to
                message.sentByUs = true;
            }
            // A message another device of ours kept: the saved chat is the same
            // chat on every device, so it arrives as one of our own lines in it.
            if (body.value("type", std::string()) == "device.saved"
                && body.value("from", std::string()) == fingerprint()) {
                if (body.value("device", std::string()) == client_->clientId()) {
                    client_->ack(entry.id);
                    continue;  // the device that saved it already has it
                }
                body = body.at("message");
                body["from"] = fingerprint();  // the saved chat is ours
                message.sentByUs = true;
            }
            message.fromFingerprint = body.at("from").get<std::string>();
            message.e2eId = body.value("id", std::string());
            message.sentAt = body.value("sentAt", static_cast<std::int64_t>(0));
            // Passed on rather than written here. Taken as the bare fact it is:
            // it names nobody and is not evidence of anything.
            message.forwarded = body.value("forwarded", false);
            std::string type = body.value("type", std::string("text"));

            // Who may be heard at all. Our own devices always; a contact always;
            // a stranger only to ask to become one. Anything else is consumed
            // where it stands - before a contact entry can be created for them,
            // before their routing is adopted, and before the user is told.
            const bool fromOurselves = message.fromFingerprint == fingerprint();
            const bool known = contacts_.find(message.fromFingerprint) != contacts_.end();
            const bool asking = type == "contact.request";
            if (!fromOurselves
                && (isBlocked(message.fromFingerprint) || (!known && !asking))) {
                client_->ack(entry.id);
                continue;
            }

            // Their routing rides on every message: adopt it the moment it moves.
            // This is the whole address-change repair - it needs one message from
            // them, in any direction, of any type.
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
                // A dialog that started from their side never carried their view
                // capability, so this is also where an older contact becomes one
                // we can hand on to somebody else - and where one who has turned
                // sharing off takes that back, by sending an empty one.
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

            // Bootstrap may ride with any content type; apply it before dispatch
            // so a new or migrated contact is established regardless of type.
            if (body.contains("bootstrap")) {
                Contact& peer = contacts_[message.fromFingerprint];
                // The keys ride with the bootstrap, and this is where a contact
                // is made: from here on their messages are checked against them.
                rememberKeys(peer, keysIn(body));
                applyBootstrap(peer, body.at("bootstrap"), client_->clientId(), soleDevice());
                message.establishedContact = true;
                establishedPeers.insert(message.fromFingerprint);
            }

            // A contact request OR its acceptance carries the sender's self-chosen
            // display name (`dn`); adopt it as this contact's initial local label so
            // we show a named friend instead of a bare fingerprint - in BOTH
            // directions (requester names the accepter and vice versa). Only seeds an
            // empty name (never overwrites a name we already hold or the user later
            // set), so a peer can never rename themselves in our contacts after the
            // fact.
            if (type == "contact.request" || type == "contact.accept") {
                const std::string dn = body.value("dn", std::string());
                Contact& peer = contacts_[message.fromFingerprint];
                if (!dn.empty() && peer.displayName.empty()) {
                    // Their own choice of name, and the one name it may not be.
                    peer.displayName = safeContactName(dn);
                }
                if (type == "contact.request") {
                    // Whoever asked gets our batch by name.
                    peer.requesterDevice = body.value("device", std::string());
                }
            }

            // The peer is low on our tokens and asked to be refilled; their request
            // prepays our reply with a fresh token, held only for that refill.
            if (body.value("lowStash", false)) {
                refillPeers.insert({message.fromFingerprint, body.value("device", std::string())});
            }
            if (body.contains("refillToken")) {
                prepaidRefillTokens[message.fromFingerprint]
                    = body.at("refillToken").get<std::string>();
            }

            // Content dispatch. An unknown type is still acked and surfaced (not
            // dropped) so a newer client could render it; see docs Messages.md.
            if (type == "text" || type == "contact.request") {
                message.contentType = type;
                message.text = body.value("text", std::string());
            } else if (type == kTypeImage) {
                // The bytes came with the message: keep them in the account and
                // let the message carry only what the chat shows.
                message.contentType = type;
                const nlohmann::json& picture = body.at("image");
                message.attachmentName = picture.value("name", std::string());
                message.attachmentMime = picture.value("mime", std::string());
                message.attachmentSize = picture.value("size", std::uint64_t{0});
                const nlohmann::json::binary_t& data = picture.at("data").get_binary();
                putPicture(message.e2eId, Bytes(data.begin(), data.end()));
            } else if (type == kTypeVoice) {
                // The audio came with the message, like a picture does.
                message.contentType = type;
                const nlohmann::json& voice = body.at("voice");
                message.attachmentMime = "audio/opus";
                message.attachmentSize = voice.value("size", std::uint64_t{0});
                message.attachmentDurationMs = voice.value("durationMs", std::int64_t{0});
                const nlohmann::json::binary_t& data = voice.at("data").get_binary();
                putVoice(message.e2eId, Bytes(data.begin(), data.end()));
            } else if (type == kTypeFile || type == "audio") {
                // An announcement, not a delivery: the bytes are still on the
                // sender's disk until we ask for them.
                message.contentType = type;
                const nlohmann::json& file = body.at("file");
                message.attachmentRef = file.value("sha256", std::string());
                message.attachmentName = file.value("name", std::string());
                message.attachmentMime = file.value("mime", std::string());
                message.attachmentSize = file.value("size", std::uint64_t{0});
            } else if (type == "file.request") {
                // Silent: a contact wants a file we announced. Only if they are
                // still waiting, though - a request is answered by building a
                // one-time destination and holding it open, and after a restart
                // the asking side remembers nothing. An old one is dropped rather
                // than served to nobody; the user asks again if they still want it.
                message.contentType = type;
                const std::int64_t askedAt = body.value("sentAt", std::int64_t{0});
                if (askedAt != 0 && nowMillis() - askedAt > kFileRequestFreshnessMs) {
                    bazarish::log::info("file request from {} is stale, not serving",
                        bazarish::log::redact(message.fromFingerprint));
                } else {
                    serveRequestedFile(message.fromFingerprint,
                        body.value("fileId", std::string()),
                        body.value("device", std::string()));
                }
            } else if (type == "file.offer") {
                // Silent: the sender is up and serving; start pulling.
                message.contentType = type;
                // The one-time address in it may have been raised for another
                // device of ours: then it is theirs to pull, and this device
                // asks for its own copy if the user wants the file here too.
                const std::string offerFor = body.value("forDevice", std::string());
                if (!offerFor.empty() && offerFor != client_->clientId()) {
                    client_->ack(entry.id);
                    continue;
                }
                try {
                    startAnnouncedFetch(
                        fileOfferFromJson(body.at("offer")), message.fromFingerprint);
                } catch (const std::exception& error) {
                    // Malformed offer: the transfer simply never starts.
                    bazarish::log::warn("file offer ignored: {}", error.what());
                }
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
                // A command invocation aimed at a bot: the command name and its
                // raw argument string. Surfaced as text too, for plain rendering.
                message.contentType = type;
                message.commandName = body.value("command", std::string());
                message.commandArgs = body.value("args", std::string());
                message.text = "/" + message.commandName
                    + (message.commandArgs.empty() ? std::string() : " " + message.commandArgs);
            } else if (type == "bot.callback") {
                // A button press: the tapped button's payload and the keyboard
                // message it belongs to.
                message.contentType = type;
                message.callbackData = body.value("data", std::string());
                message.refId = body.value("ref", std::string());
            } else if (type == "edit") {
                // An in-place edit of a message the sender previously sent: the new
                // text (and keyboard, via the generic block below). refId is the
                // target message's id.
                message.contentType = type;
                message.refId = body.value("ref", std::string());
                message.text = body.value("text", std::string());
            } else if (type == "delete") {
                // A delete-for-everyone of a message the sender previously sent:
                // refId is the target message's id; the client drops it.
                message.contentType = type;
                message.refId = body.value("ref", std::string());
            } else if (type == "receipt") {
                // A receipt: the recipient's client received one of our sent
                // messages (the green state). Carries the acknowledged message id.
                // The amber "delivered to the recipient's server" state is reported
                // by our own server (the send attempt), not by this receipt.
                message.contentType = type;
                message.refId = body.value("ref", std::string());
            } else if (type == "reaction") {
                // A reaction to a message: `ref` is the target message id, `text` the
                // emoji (empty removes the reactor's reaction). The reactor is the
                // message's verified `from`. The UI records it against the target
                // message and never renders it as a chat bubble.
                message.contentType = type;
                message.refId = body.value("ref", std::string());
                message.text = body.value("text", std::string());
                // Their client is not ours to trust: a reaction past the limits is
                // dropped rather than rendered as a paragraph on someone's message.
                if (!reactionWithinLimits(message.text)) {
                    bazarish::log::info("oversized reaction from {} ignored",
                        bazarish::log::redact(message.fromFingerprint));
                    client_->ack(entry.id);
                    continue;
                }
            } else if (type == "call.invite" || type == "call.accept" || type == "call.decline"
                || type == "call.end" || type == "call.ring" || type == "call.taken") {
                // Audio-call signalling: update call state and start/stop media. The
                // media itself never touches the server (it rides I2P datagrams).
                handleCallSignal(type, message.fromFingerprint, body, message);
            } else if (type == "token-request") {
                // One of their devices has no capacity to write to us. Answer it
                // by name; the reply rides the contact channel when we hold none
                // of their tokens either, which is the usual case right after a
                // new device appears.
                message.contentType = type;
                refillPeers.insert({message.fromFingerprint, body.value("device", std::string())});
            } else if (type == "token-refill") {
                // The fresh tokens already arrived via the bootstrap block.
                message.contentType = type;
            } else if (type == "token.request") {
                // A contact asking to be topped up. Everything it carries - the
                // ask, the device to answer, the token that prepays the answer -
                // was taken above; there is nothing to show and nothing else to
                // do here.
                message.contentType = type;
            } else if (type == "device.delegation-term") {
                // Another device changed the account's delegation term. Adopt it
                // and, when it is shorter than what is out there, re-issue now:
                // otherwise the longer delegation already on the server would
                // keep this device standing down until it lapsed.
                message.contentType = type;
                if (body.value("device", std::string()) != client_->clientId()) {
                    const std::int64_t days = body.value("days", kDefaultDelegationDays);
                    if (days >= kMinDelegationDays && days <= kMaxDelegationDays
                        && days != delegationDays_) {
                        setDelegationDays(days, false);
                    }
                }
            } else if (type == "device.contacts-request") {
                // Another device of ours has no address book. Every device that
                // has one answers; the asker takes them all and keeps the first
                // complete answer for each contact.
                message.contentType = type;
                if (body.value("device", std::string()) != client_->clientId()) {
                    sendContactBookTo(body.value("device", std::string()));
                }
            } else if (type == "device.contacts") {
                // The book, or a part of it, from one of our devices.
                message.contentType = type;
                if (body.value("forDevice", std::string()) == client_->clientId()
                    && body.contains("contacts")) {
                    applyContactBook(body.at("contacts"));
                }
            } else if (type == "device.token-request") {
                // Another of our devices has nothing left to write to this peer
                // with. Give it one of ours if we have any; every device that
                // does answers, and the asker keeps what arrives.
                message.contentType = type;
                if (body.value("device", std::string()) != client_->clientId()) {
                    grantTokenToDevices(body.value("peer", std::string()),
                        body.value("device", std::string()));
                }
            } else if (type == "device.token-grant") {
                // A token another of our devices gave up for us. The first one
                // buys a batch of our own; the rest are ours to keep, and they
                // are gone from the device that sent them.
                message.contentType = type;
                if (body.value("forDevice", std::string()) == client_->clientId()) {
                    const std::string peer = body.value("peer", std::string());
                    const std::string token = body.value("token", std::string());
                    const auto known = contacts_.find(peer);
                    if (known != contacts_.end() && !token.empty()) {
                        Contact& contact = known->second;
                        if (std::find(contact.sendTokens.begin(), contact.sendTokens.end(), token)
                            == contact.sendTokens.end()) {
                            contact.sendTokens.push_back(token);
                        }
                        persistContacts();
                        if (contact.needsOwnBatch || contact.sendTokens.size() == 1) {
                            sendTokenRequest(peer);
                        }
                    }
                }
            } else if (type == "device.i2p-master") {
                // A self-sync from another of our devices: adopt the I2P master if we
                // do not already hold one, so this device keeps the same address.
                // Idempotent (a device that already has it ignores it) and handled
                // silently - not a user-visible message.
                message.contentType = type;
                if (message.fromFingerprint == fingerprint() && i2pMaster_.empty()) {
                    try {
                        loadI2pDestination(fromBase64(body.at("i2pMaster").get<std::string>()));
                    } catch (const std::exception& error) {
                        // Malformed, wrong key type, or already configured. This device
                        // then keeps an address of its own, which is worth knowing.
                        bazarish::log::warn("master key from another device rejected: {}",
                            error.what());
                    }
                }
            } else if (type == "avatar") {
                // A contact pushed their avatar (silent service message): store it
                // and surface the bytes so the UI's avatar store updates. Never a
                // chat bubble.
                message.contentType = type;
                try {
                    const nlohmann::json& av = body.at("avatar");
                    const Bytes data = fromBase64(av.value("data", std::string()));
                    storeContactAvatar(
                        message.fromFingerprint, data, av.value("mime", std::string()));
                    message.avatarData = std::string(data.begin(), data.end());
                } catch (const std::exception& error) {
                    // Malformed avatar payload: ignore.
                    bazarish::log::warn("contact avatar ignored: {}", error.what());
                }
            } else if (type == "device.avatar") {
                // Our own avatar from another of our devices: adopt it. Silent.
                message.contentType = type;
                if (message.fromFingerprint == fingerprint()) {
                    try {
                        const nlohmann::json& av = body.at("avatar");
                        const Bytes data = fromBase64(av.value("data", std::string()));
                        storeOwnAvatar(data, av.value("mime", std::string()));
                        message.avatarData = std::string(data.begin(), data.end());
                    } catch (const std::exception& error) {
                        // Malformed avatar payload: ignore.
                        bazarish::log::warn("own avatar from another device ignored: {}",
                            error.what());
                    }
                }
            } else if (type == "device.contact-name") {
                // A contact rename mirrored from another of our devices: apply it
                // locally (purely a local label). Silent.
                message.contentType = type;
                if (message.fromFingerprint == fingerprint()) {
                    const auto named = contacts_.find(body.value("peer", std::string()));
                    if (named != contacts_.end()) {
                        named->second.displayName
                            = safeContactName(body.value("name", std::string()));
                    }
                }
            } else if (type == "device.chat-pin") {
                // A pin/unpin mirrored from another of our devices. The pin list lives
                // in the client's local store, so surface it (the peer in refId, the
                // pinned flag in text) for the GUI to apply. Honoured only from us.
                message.contentType = type;
                if (message.fromFingerprint == fingerprint()) {
                    message.refId = body.value("peer", std::string());
                    message.text
                        = body.value("pinned", false) ? std::string("1") : std::string("0");
                }
            } else if (type == "device.chat-clear") {
                // Another device of ours emptied its copy of a conversation; the
                // GUI wipes the same one here. Honoured only from us.
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    message.refId = body.value("peer", std::string());
                }
            } else if (type == "device.account-name") {
                // The account was renamed on another device of ours.
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
                // An account-wide answer changed on another device of ours.
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    // Absent means unchanged, not "back to the default": a notice
                    // says what it knows about.
                    const bool accept = body.value("acceptCalls", acceptCalls_);
                    const bool receipts = body.value("sendReceipts", sendReceipts_);
                    if (accept != acceptCalls_ || receipts != sendReceipts_) {
                        acceptCalls_ = accept;
                        sendReceipts_ = receipts;
                        persistMeta();
                    }
                }
            } else if (type == "device.saved-clear") {
                // Another device of ours emptied the saved chat; the GUI wipes its
                // transcript for that chat on receipt. Honoured only from us.
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                }
            } else if (type == "device.contact-remove") {
                // Another device of ours removed a contact. The removal is the
                // same here as it was there, and the GUI wipes the transcript.
                if (message.fromFingerprint == fingerprint()) {
                    message.contentType = type;
                    message.refId = body.value("peer", std::string());
                    removeContact(message.refId);
                }
            } else if (type == "device.contact-block") {
                // Another device of ours blocked or unblocked somebody. The tokens
                // were revoked by the device that did it - one request is enough.
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
            } else if (type == "device.contact-prefs") {
                // Another device of ours changed what a contact may do here.
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
                // The peer asked to clear our whole conversation with them; the GUI
                // wipes its transcript on receipt. No core state changes here.
                message.contentType = type;
            } else if (type == "contact.accept") {
                // The peer agreed to our contact request: their descriptor + reply
                // tokens already rode in the bootstrap block above, so we are now a
                // mutual contact. Surfaced as a system note by the UI.
                message.contentType = type;
            } else {
                message.contentType = "unsupported";
                message.rawType = type;
            }

            // An inline keyboard may ride on any content message (typically text);
            // preserve it as its wire form so a UI can render the buttons.
            if (body.contains("keyboard")) {
                message.keyboardJson = body.at("keyboard").dump();
            }
            // A reply reference (the replied-to message's protocol id) may ride on
            // any content message; preserve it so the UI can render a quote/link.
            if (body.contains("replyTo")) {
                message.replyTo = body.value("replyTo", std::string());
            }

            // Ack now (CLI/bots), or defer to the caller (GUI). Deferring acks a
            // surfaced item only after the client has durably stored it, so a
            // crash/restart between fetch and store never loses it. Re-processing on
            // a pre-ack re-fetch is safe - applyBootstrap dedups tokens and the GUI
            // dedups by e2eId.
            if (autoAckSurfaced) {
                client_->ack(entry.id);
            } else {
                message.pendingId = entry.id;
            }
            noteWire(false,
                (message.contentType.empty() ? std::string("content") : message.contentType)
                    + " from " + wireName(message.fromFingerprint),
                {}, "id " + entry.id.substr(0, std::min(entry.id.size(), kShortFingerprintChars)));
            result.push_back(std::move(message));
        } catch (const std::exception& error) {
            // Isolate a poison item: a single unreadable pending entry must
            // never throw out of the whole sync. That would leave it unacked,
            // blocking every later item and pinning the account at
            // "connecting" forever. Consume it so the mailbox unblocks and
            // carry on; the bytes are already delivered to us, we just cannot
            // read them. If the ack itself fails the server is unreachable, so
            // the exception propagates and the caller retries the whole tick.
            bazarish::log::warn(
                "sync: dropping unreadable pending item: {}", error.what());
            noteWire(false, "unreadable item", "dropped", error.what());
            client_->ack(entry.id);
        }
    }
    persistContacts();

    // A peer accepted our request (or we just learned their routing): push our
    // avatar to any now-established contact we have engaged with. maybeSend... is
    // gated on issuedToThem, so an un-accepted incoming request never triggers an
    // automatic avatar reply. Best effort, after the loop like the refills below.
    for (const std::string& peer : establishedPeers) {
        maybeSendAvatarToContact(peer);
    }

    // Refill peers that ran low (a fresh token batch, sent as a token-refill).
    // Done after the loop so the outbound send never races the fetch loop.
    // A device that took one token out of an unaddressed batch owes itself a
    // batch of its own: spend it now rather than at the first message, so the
    // shared pool stops being shared as early as possible.
    for (auto& [peerFingerprint, contact] : contacts_) {
        if (!contact.needsOwnBatch || contact.sendTokens.empty()) {
            continue;
        }
        try {
            sendTokenRequest(peerFingerprint);
        } catch (const std::exception& error) {
            bazarish::log::warn("sync: could not ask {} for this device's own tokens: {}",
                bazarish::log::redact(peerFingerprint), error.what());
        }
    }
    for (const auto& [peer, device] : refillPeers) {
        // Best-effort: a peer we cannot route to right now must not fail the
        // whole sync (which would read as "server unreachable"); retry next tick.
        try {
            const auto pre = prepaidRefillTokens.find(peer);
            sendTokenRefill(peer, device,
                pre != prepaidRefillTokens.end() ? pre->second : std::string());
        } catch (const std::exception& error) {
            bazarish::log::warn("sync: token refill failed: {}", error.what());
        }
    }
    // Once per device, on the first sync that reached the server: ask the other
    // devices of this account for the address book. A device that is the only
    // one gets no answer, and the question costs it one self-addressed message.
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
    if (!pendingId.empty()) {
        client_->ack(pendingId);
    }
}

void Session::sendTokenRefill(const std::string& peerFingerprint, const std::string& forDevice,
    const std::string& prepaidToken)
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        return;
    }
    const Contact& contact = found->second;
    // Never auto-refill a peer whose incoming request we have not accepted yet
    // (issuedToThem still false): that would attach our bootstrap and silently
    // establish the contact. We also need the peer's descriptor. With a prepaidToken
    // (embedded in their low-stash request) the reply spends exactly it, so it lands
    // even when we hold none of their tokens; without one we spend one of ours, so an
    // empty stash means the peer's own refill of us must arrive first.
    if (!contact.issuedToThem || contact.sealingPublicB64.empty()
        || contact.servingSealingB64.empty()) {
        return;
    }
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "token-refill"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"bootstrap", {{"replyTokens", issueTokenBatch(peerFingerprint)}, {"forDevice", forDevice}}},
        {"routing",
            {{"dest", myDest_}, {"servingKey", myServingKeyB64_}, {"view", sharedView()}}},
    };
    if (!prepaidToken.empty() || !contact.sendTokens.empty()) {
        sendContent(peerFingerprint, std::move(inner), {}, false, true, prepaidToken);
        return;
    }
    // Neither side has capacity for the other: their device asked because it had
    // nothing, and we have nothing of theirs to spend on the answer. The tokenless
    // contact channel exists for exactly this - otherwise the two of them would
    // wait on each other forever.
    const Bytes innerBytes = encodedBody(inner);
    const Key peerSealing = Key::fromPublicDer(fromBase64(contact.sealingPublicB64));
    const Bytes payload = cms::seal(innerBytes, peerSealing);
    const Key peerServingKey = Key::fromPublicDer(fromBase64(contact.servingSealingB64));
    deliver(contact.dest, peerServingKey, "contact", peerFingerprint, std::nullopt, payload);
}

std::size_t Session::sendCapacity(const std::string& peerFingerprint) const
{
    const auto found = contacts_.find(peerFingerprint);
    return found == contacts_.end() ? 0 : found->second.sendTokens.size();
}

namespace {

// Where a message's picture is kept in the account database.
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

void Session::closeAccountOnServer()
{
    client_->closeAccount();
}

void Session::echoSentToSelf(const std::string& peerFingerprint, const nlohmann::json& inner)
{
    if (myDest_.empty() || myServingKeyB64_.empty()) {
        return;  // our own routing is not known yet
    }
    const nlohmann::json echo = {
        {"v", kMessageFormatVersion},
        {"type", "device.message"},
        {"id", toHex(randomBytes(16))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"peer", peerFingerprint},
        {"device", client_->clientId()},
        {"message", inner},
    };
    submitSignedToSelf(echo, "device.message");
}

void Session::sendTokenRequest(const std::string& peerFingerprint)
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end()) {
        return;
    }
    Contact& contact = found->second;
    if (contact.sealingPublicB64.empty() || contact.servingSealingB64.empty()) {
        return;  // no descriptor yet: nothing to ask, and nowhere to ask it
    }
    if (contact.sendTokens.empty()) {
        // Nothing to spend, so nothing to ask with. The way out is a token
        // borrowed from another of this account's own devices, not a tokenless
        // write into a stranger's mailbox.
        askDevicesForToken(peerFingerprint);
        return;
    }
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "token-request"},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"device", client_->clientId()},
        {"routing",
            {{"dest", myDest_}, {"servingKey", myServingKeyB64_}, {"view", sharedView()}}},
    };
    // Spends one of our tokens like any other message: the peer answers with a
    // batch addressed to this device, and no other device of ours holds it.
    sendContent(peerFingerprint, std::move(inner));
    contact.needsOwnBatch = false;
    persistContacts();
}

bool Session::soleDevice() const
{
    try {
        const std::vector<Client::DeviceEntry> devices = client_->listClients();
        return devices.size() <= 1;
    } catch (const std::exception& error) {
        // Unknown means "assume there are others": taking one token and asking
        // for a batch costs a round trip, while wrongly keeping a shared batch
        // costs another device its tokens.
        bazarish::log::info("device list unavailable, treating this as one of several: {}",
            error.what());
        return false;
    }
}

void Session::askDevicesForContacts()
{
    // The one thing a fresh device cannot get from the network: a contact is
    // reached by destination and read by capability, and there is no lookup that
    // turns a fingerprint into either. The account's other devices hold the book.
    const nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "device.contacts-request"},
        {"id", toHex(randomBytes(16))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"device", client_->clientId()},
    };
    submitSignedToSelf(inner, "device.contacts-request");
}

nlohmann::json Session::contactBookEntry(
    const std::string& peerFingerprint, const Contact& contact) const
{
    // What a contact IS: who they are, where they are reached and what this
    // account decided about them. Nothing that belongs to one device or to one
    // exchange in flight - above all no delivery tokens, which are one-time and
    // spending one twice is losing a message.
    nlohmann::json entry = {
        {"peer", peerFingerprint},
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
    // Sent in as many messages as it takes: one contact never spans two, and an
    // avatar that would not fit is left behind rather than splitting the entry -
    // the correspondent sends it again themselves the next time they write.
    std::vector<nlohmann::json> chunk;
    std::size_t chunkBytes = 0;
    int seq = 0;
    const auto flush = [&](const bool last) {
        if (chunk.empty() && !last) {
            return;
        }
        const nlohmann::json inner = {
            {"v", kMessageFormatVersion},
            {"type", "device.contacts"},
            {"id", toHex(randomBytes(16))},
            {"from", fingerprint()},
            {"sentAt", nowMillis()},
            {"device", client_->clientId()},
            {"forDevice", toDevice},
            {"seq", seq++},
            {"last", last},
            {"contacts", chunk},
        };
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
            flush(false);
        }
        chunkBytes += entryBytes;
        chunk.push_back(std::move(entry));
    }
    flush(true);
}

void Session::applyContactBook(const nlohmann::json& entries)
{
    // Gaps only. What this device knows about a contact it already has stands:
    // routing learned from the correspondent themselves is fresher than a copy
    // of it, and a duplicate must not undo a rename or a move.
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
            // No tokens travel, so this device has nothing to write with yet: it
            // asks the others for one, which is the path that already exists.
            contact.needsOwnBatch = true;
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

void Session::askDevicesForToken(const std::string& peerFingerprint)
{
    const nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "device.token-request"},
        {"id", toHex(randomBytes(16))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"device", client_->clientId()},
        {"peer", peerFingerprint},
    };
    submitSignedToSelf(inner, "device.token-request");
}

void Session::grantTokenToDevices(
    const std::string& peerFingerprint, const std::string& toDevice)
{
    const auto found = contacts_.find(peerFingerprint);
    if (found == contacts_.end() || found->second.sendTokens.empty()) {
        return;  // nothing to give: another device may still have one
    }
    Contact& contact = found->second;
    // Exactly one, and it leaves this device with it: a one-time token in two
    // places is a token one of them will be refused for.
    const std::string token = contact.sendTokens.back();
    contact.sendTokens.pop_back();
    persistContacts();

    const nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "device.token-grant"},
        {"id", toHex(randomBytes(16))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"device", client_->clientId()},
        {"forDevice", toDevice},
        {"peer", peerFingerprint},
        {"token", token},
    };
    submitSignedToSelf(inner, "device.token-grant");
}

// ============================ Audio calls ============================

void Session::setAudioBackend(AudioSourceFactory sourceFactory, AudioSinkFactory sinkFactory)
{
    audioSourceFactory_ = std::move(sourceFactory);
    audioSinkFactory_ = std::move(sinkFactory);
}

std::shared_ptr<bazarish::i2p::Endpoint> Session::openCallMediaSession()
{
    // Call media rides a one-time encrypted-LS (b33) destination on the embedded
    // router, published so the peer can send RAW media datagrams to it; torn down
    // with the call. Minimal-length tunnels (1 hop each way, no variance): the
    // single biggest latency/jitter lever for realtime media. Safe here because
    // the media destination is one-time and unlinked from the identity
    // destination, so a short tunnel never weakens identity anonymity.
    return i2pRouter().createEndpoint(bazarish::i2p::EndpointConfig{
        i2pRouter().generateKeys(), bazarish::i2p::LeaseSetKind::eEncrypted,
        bazarish::i2p::Privacy::eMinimal, bazarish::i2p::kDefaultTunnelQuantity, true,
        "Call media", destinationOwner()});
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
    // Both sides start counting when media is proven in BOTH directions. The
    // first datagram received is not that moment: the caller hears the callee as
    // soon as the accept arrives, while the callee cannot hear the caller until
    // its own destination has published, which is seconds later.
    call_.media->setOnConnected([this]() {
        if (call_.connectedAtMs == 0) {
            call_.connectedAtMs = nowMillis();
            call_.stage.clear();  // talking: no stage to report any more
        }
    });
    call_.media->start();
}

void Session::clearCall()
{
    if (call_.media) {
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
    // Every device of this account is shown the same invitation, and every one of
    // them keeps ringing until it hears otherwise. The device that answers or
    // refuses says so, and the rest drop the call without recording anything: the
    // device that took it owns the outcome.
    const nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", "call.taken"},
        {"id", toHex(randomBytes(16))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
        {"device", client_->clientId()},
        {"callId", callId},
    };
    try {
        submitSignedToSelf(inner, "call.taken");
    } catch (const std::exception& error) {
        // The call this device is taking matters more than the other devices'
        // ringing, which stops on its own at the ring timeout.
        bazarish::log::warn("other devices not told the call was taken: {}", error.what());
    }
}

bool Session::sendCallSignal(
    const std::string& peerFingerprint, const std::string& type, nlohmann::json extra)
{
    nlohmann::json inner = {
        {"v", kMessageFormatVersion},
        {"type", type},
        {"id", toHex(randomBytes(8))},
        {"from", fingerprint()},
        {"sentAt", nowMillis()},
    };
    for (const auto& field : extra.items()) {
        inner[field.key()] = field.value();
    }
    // The return says the peer's server stored it, which for an invitation is the
    // difference between "still on its way" and "their phone is ringing".
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
    // Build the media destination first (strict I2P); only then announce the call.
    call_.stage = "Preparing your call address";
    auto dgram = openCallMediaSession();
    const std::string callId = toHex(randomBytes(8));
    const Bytes mediaKey = randomBytes(kAeadKeyBytes);
    const bool delivered = sendCallSignal(peerFingerprint, "call.invite",
        {
            {"callId", callId},
            {"media", "audio"},
            {"codec", "opus"},
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
        {{"callId", callId}, {"media", "audio"},
            {"dest", dgram->routingHost()}});
    announceCallTaken(callId);
    call_.dgram = std::move(dgram);
    call_.state = CallState::eActive;
    // Accepted is not connected: the tunnels between the two media destinations
    // still have to meet. Both sides say the same thing here and both stop
    // saying it at the same moment - when the first packet arrives.
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
    // What this account answers, wherever it is reached from: a caller must hear
    // the same thing and a correspondent must be told - or not told - the same
    // thing, whichever device of ours happens to be reading.
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
        // The local call is already cleared; a failed signal only leaves the
        // caller to time out on its own.
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
    // Active: a normal hang-up (answered). Still ringing: we gave up - outgoing is a
    // cancel, an incoming one we end is a decline.
    const CallOutcome outcome = call_.state == CallState::eActive
        ? CallOutcome::eAnswered
        : (call_.initiator ? CallOutcome::eCancelled : CallOutcome::eDeclined);
    logCompletedCall(outcome);
    clearCall();
    try {
        sendCallSignal(peer, "call.end", {{"callId", callId}});
    } catch (const std::exception& error) {
        // The call is over locally either way; the peer falls back to its timeout.
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
        if (call_.state != CallState::eIdle && call_.callId == message.callId) {
            // The same invite again - a redelivery, not a second caller. Declining
            // it told the caller "busy" for the very call this side had already
            // taken, so one side sat in the call while the other showed busy.
            bazarish::log::info("duplicate call invite ignored");
            return;
        }
        if (!acceptCalls_ || !contactCalls(from)) {
            // Either this account takes no calls right now, or it takes none from
            // them. Answer at once so the caller sees a refusal instead of ringing
            // into nothing; either setting can be turned back on any time, which is
            // why the caller's call button stays where it is. The call is written
            // into the conversation like any other - a refused call is still a
            // call that came.
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
            // Already busy: decline so the caller is not left ringing.
            try {
                sendCallSignal(
                    from, "call.decline", {{"callId", message.callId}, {"reason", "busy"}});
            } catch (const std::exception& error) {
                bazarish::log::warn("busy signal not delivered: {}", error.what());
            }
            // We could not take this call: record it as a missed call from that peer.
            pendingCallLog_.push_back({from, true, CallOutcome::eMissed, 0});
            message.text = "busy";
            return;
        }
        Bytes key;
        try {
            key = fromBase64(body.value("key", std::string()));
        } catch (const std::exception& error) {
            // Surface the event but do not ring: a call we cannot key is a call we
            // cannot take, and a silent one looks like the peer never called.
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
        // Without this the ring timeout never ran on this side, and an invitation
        // nobody answered rang until the application was closed.
        call_.startedAtMs = nowMillis();
        try {
            // Tell the caller a device of ours is showing the call: that is the
            // moment their side can stop guessing and start ringing.
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
        // Another device of this account answered or declined the very call this
        // one is showing. It is not a missed call and not one to record: the
        // device that took it owns the outcome.
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

    // call.decline / call.end: record the outcome and tear the call down if it is
    // the one we track.
    if (call_.state != CallState::eIdle && call_.callId == message.callId
        && from == call_.peerFingerprint) {
        if (type == "call.decline" && call_.state != CallState::eOutgoing) {
            // A decline from an account with several devices: one of them took the
            // call, another said no. The one that answered is the one that counts.
            return;
        }
        CallOutcome outcome;
        if (type == "call.decline") {
            // The peer rejected our outgoing call (busy vs an explicit decline).
            const std::string reason = body.value("reason", std::string());
            if (reason == "busy") {
                outcome = CallOutcome::eBusy;
            } else if (reason == "refused") {
                outcome = CallOutcome::eRefused;
            } else {
                outcome = CallOutcome::eDeclined;
            }
        } else if (call_.state == CallState::eActive) {
            outcome = CallOutcome::eAnswered;  // normal hang-up after connecting
        } else if (call_.state == CallState::eIncoming) {
            outcome = CallOutcome::eMissed;  // the caller cancelled before we answered
        } else {
            outcome = CallOutcome::eDeclined;  // outgoing torn down before it connected
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
    // incoming = we did not initiate; the peer is the other party either way.
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
        return;  // no call
    }
    if (call_.state == CallState::eOutgoing && call_.deliveredAtMs == 0) {
        // Still trying to hand the invitation over: retry through the normal
        // delivery path so a momentary outage does not end the call.
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
    // A call the other side has left: their "end" travels the mailbox and can be
    // lost or slow, and media stops the moment they hang up. Keep-alives run
    // twice a second, so silence this long is unambiguous - without it the call
    // sat at "in call" forever, holding its media destination up with it.
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
    // The ring window runs from the moment their device started showing the call
    // when it said so, and from delivery to their server otherwise: giving up
    // while the far end has only just begun ringing is what leaves one side
    // ringing after the other has given up.
    const std::int64_t since = call_.peerRingingAtMs > 0 ? call_.peerRingingAtMs
        : (call_.deliveredAtMs > 0 ? call_.deliveredAtMs : call_.startedAtMs);
    if (nowMillis() - since <= kRingTimeoutMs) {
        return;  // still ringing (active calls sit here too, which is intended)
    }
    if (call_.state == CallState::eOutgoing) {
        const std::string peer = call_.peerFingerprint;
        const std::string callId = call_.callId;
        logCompletedCall(CallOutcome::eNoAnswer);
        clearCall();
        try {
            sendCallSignal(peer, "call.end", {{"callId", callId}});  // stop the peer ringing
        } catch (const std::exception& error) {
            bazarish::log::warn("end signal not delivered: {}", error.what());
        }
    } else if (call_.state == CallState::eIncoming) {
        logCompletedCall(CallOutcome::eMissed);
        clearCall();  // the caller times out symmetrically; no signal needed
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
    // A re-publish grants nothing; the point is the routing the server now has
    // and our card does not.
    storeCard(client_->publishCard(sealingKey_.publicDer(), ownRoutingHost()));
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
    // Enough of a fingerprint to tell two unnamed accounts apart at a glance.
    constexpr std::size_t kOwnerFingerprintChars = 8;
    return name_.empty() ? fingerprint().substr(0, kOwnerFingerprintChars) : name_;
}

std::string Session::inviteUri() const
{
    if (myDest_.empty() || view_.empty()) {
        throw std::runtime_error("register first: no destination to publish");
    }
    // The invite is a small descriptor: fingerprint, our own destination, and
    // the capability that reads our card. No key travels in it - the contact
    // takes the serving key out of the card it fetches and verifies.
    Descriptor descriptor;
    descriptor.fingerprint = fingerprint();
    descriptor.dest = myDest_;
    descriptor.view = view_;
    // Advertise our account name so the contact can adopt it as our display name.
    descriptor.name = name_;
    return encodeDescriptor(descriptor);
}

void Session::changePassphrase(const std::string& passphrase)
{
    db_->rekey(passphrase);
    encrypted_ = !passphrase.empty();
    persistMeta();
}

void Session::exportAccount(const fs::path& outFile, const std::string& password) const
{
    const nlohmann::json meta = nlohmann::json::parse(db_->text("meta"));
    // Use the in-memory contacts; the bundle carries them in the clear (the
    // bundle password is the protection).
    const nlohmann::json contacts = contactsToJson();

    // The keys are re-serialized unencrypted inside the bundle; the password
    // protects the bundle as a whole, decoupling the export from whatever
    // at-rest passphrase this account directory happens to use.
    const nlohmann::json bundle = {
        {"v", 1},
        {"identityPem", client_->identity().privatePem()},
        {"sealingPem", sealingKey_.privatePem()},
        {"meta", meta},
        {"contacts", contacts},
        // Who this account has cut off travels with it: a restored account that
        // forgot its block list would let them all back in.
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

    // The new account's database is keyed with the chosen passphrase; the keys go
    // inside it as they are.
    AccountDb db(accountFile, atRestPassphrase);
    const Identity identity = Identity::fromPrivatePem(bundle.at("identityPem").get<std::string>());
    const Key sealing = Key::fromPrivatePem(bundle.at("sealingPem").get<std::string>());
    db.putText("identity.pem", identity.privatePem());
    db.putText("sealing.pem", sealing.privatePem());

    nlohmann::json meta = bundle.at("meta");
    meta["encrypted"] = !atRestPassphrase.empty();
    // A client id names a DEVICE, not an account. Carried over from the bundle,
    // both devices would present the same one: the server would hold a single
    // pending list for them, and whichever fetched first would ack the mail away
    // from the other. A fresh id makes this an added device, which is what an
    // import is, and each gets its own copy of everything that arrives.
    meta["clientId"] = toHex(randomBytes(8));
    // Everything else in the meta is carried as it is - the delivery-id seed above
    // all: it names the envelopes this account has already sent, and a restored
    // account that renamed them would deliver copies of messages the recipients'
    // servers would no longer recognise.

    db.putText("meta", meta.dump(2));
    db.putText("contacts", bundle.at("contacts").dump());
    if (bundle.contains("blocked")) {
        db.putText("blocked", bundle.at("blocked").dump());
    }
}

}  // namespace bazarish::client
