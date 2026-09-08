// Bazarish project (c) 2026
#pragma once

#include "LoginSigner.hpp"

#include "AudioIo.hpp"
#include "CallMedia.hpp"
#include "Authorship.hpp"
#include "Client.hpp"
#include "FileTransfer.hpp"
#include "OutboundLeases.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Limits.hpp>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <deque>
#include <set>
#include <string>
#include <vector>

namespace bazarish::client {

class AccountDb;

// How a send reports itself back to whoever asked for it: where it has got to,
// and how it ended. Both callbacks run on a delivery worker thread, not on the
// thread that asked for the send, and the outcome one runs exactly once.
struct DeliveryWatch {
    OutboundCourier::PhaseFn onPhase;
    OutboundCourier::OutcomeFn onOutcome;
};

// One button of an inline keyboard attached to a message. Carries a label and
// exactly one action: a callback (sends a bot.callback when tapped) or a
// command (sends a bot.command). When both are set, the callback wins.
struct InlineButton {
    std::string text;
    std::string data;     // callback payload (bot.callback); empty if none
    std::string command;  // command name (bot.command); empty if none
};

// An inline keyboard: rows of buttons rendered under a message. Tapping a
// button sends a bot.callback or bot.command back to the message's sender.
using InlineKeyboard = std::vector<std::vector<InlineButton>>;

// Serializes an inline keyboard to its JSON wire form (the value of a message
// "keyboard" field). Exposed for the bot framework, the CLI and tests.
std::string inlineKeyboardJson(const InlineKeyboard& keyboard);

// A known contact's routing and admission state, persisted by the session.
// What the saved-messages chat is called, and therefore the one name a contact
// may not have: a contact whose name would be this is shown with a mark in front
// of it, so nothing in the chat list can pretend to be that chat.
inline constexpr char kSavedChatName[] = "Saved messages";
inline constexpr char kContactNamePrefix[] = "(Contact) ";

// Returns the name a contact may actually carry: `proposed` untouched, unless it
// claims the saved chat's name, in which case it is marked as a contact's.
std::string safeContactName(const std::string& proposed);

struct Contact {
    // The peer's user sealing public key (SubjectPublicKeyInfo DER, base64),
    // used to E2E-encrypt message payloads to this contact.
    std::string sealingPublicB64;
    // The peer's I2P serving destination - where delivery envelopes are routed.
    std::string dest;
    // The peer's serving sealing public key (SPKI DER, base64): delivery
    // envelopes to this contact are sealed to it (held by the peer's server).
    std::string servingSealingB64;
    // The contact's card-read capability, from the descriptor we added them by
    // or from the routing on any message of theirs: kept so their invite can be
    // passed on.
    std::string view;
    // They sent routing with no capability in it: they have turned sharing off,
    // which is a different thing from not having told us yet.
    bool sharingRefused = false;
    // The delivery pass (base64) this peer issued to us: what admits everything
    // we write into their mailbox. One value, used by every device of ours, for
    // as long as they let us write.
    std::string sendPass;
    // Whether we have already issued our pass to this peer (so they can write to
    // us). Set on the contact request, or - for a request we agreed to - only
    // once that acceptance is confirmed stored by their server: until it is in
    // their mailbox they cannot answer, so a contact marked accepted here would
    // be a dialog that exists on one side.
    bool issuedToThem = false;
    // An acceptance whose bootstrap is on its way. Not persisted: a client that
    // closes mid-flight has no proof it ever landed, so the request is pending
    // again on the next run and is agreed to afresh. It keeps a second Agree
    // from acting while the first is in the air.
    bool acceptInFlight = false;
    // Local display name for this contact: the alias used when adding, or the
    // name carried in the invite. Purely local - never sent to the peer and
    // never overwritten by anything the peer sends. The user may rename it, and
    // that rename is mirrored only to the account's own other devices.
    std::string displayName;
    // The peer's identity public keys (SPKI DER, base64): what every message of
    // theirs is checked against. Learned once - from their card when we add them,
    // or from the block on their contact request or first reply - and kept, so
    // their later messages need not carry them.
    std::string identityClassicalB64;
    std::string identityPqB64;
    // The peer's avatar as last received (raw PNG/JPEG bytes) and its mime; the
    // bytes live in a sealed per-contact file, only the mime rides in the JSON.
    Bytes avatar;
    std::string avatarMime;
    // Whether we have already pushed our own avatar to this peer, so it is sent
    // once on establishing the dialog (not on every sync). Reset when our avatar
    // changes, so the new one is re-broadcast.
    bool avatarSentToPeer = false;
    // Whether a message from this contact may announce itself outside the window,
    // and whether they may call. The account's own choice per contact; the global
    // settings still apply on top of both.
    bool notifications = true;
    bool allowCalls = true;
};

// A decrypted item pulled from the mailbox during sync.
struct IncomingMessage {
    // End-to-end content type: "text", "contact.request",
    // "file", ... or "unsupported" for a type this client cannot render.
    std::string contentType;
    std::string fromFingerprint;
    // Plain text for "text" and "contact.request"; empty for control types.
    std::string text;
    // Server-visible delivery class this arrived under ("content"/"contact").
    std::string deliveryClass;
    // True when this is another device of ours echoing a message WE sent: the
    // content is the message as sent, and fromFingerprint is the contact it went
    // to, so it belongs in that conversation as an outgoing line.
    bool sentByUs = false;
    // True when this item carried bootstrap (the peer's sealing key, serving
    // server and a fresh pass) - a new or refreshed contact.
    bool establishedContact = false;
    // The original type string when contentType == "unsupported".
    std::string rawType;
    // The sender's protocol message id (envelope "id"), used to send a
    // delivery receipt back for it.
    std::string e2eId;
    // The sender passed this on rather than writing it: a bare mark, carrying
    // nothing about where it came from or who wrote it first.
    bool forwarded = false;
    // The server-side pending-blob id this item was fetched as. NOT acked during
    // sync(): the surfaced item is acked only after the client has durably stored
    // it (ackPending, driven by the GUI after persistence), so a crash/restart
    // between fetch and store never loses it. Empty for items the core consumed
    // itself (acked in sync()).
    std::string pendingId;
    // The sender's send time (envelope "sentAt", unix milliseconds). The
    // recipient orders by it and shows it as the message time, not the receive
    // time (docs-main Messages.md "Ordering and timestamps"). 0 when absent.
    std::int64_t sentAt = 0;
    // For contentType == "receipt", the message id being acknowledged; for
    // contentType == "bot.callback", the keyboard message the button belongs to.
    std::string refId;

    // When this message replies to another, the protocol id of that original
    // message (so the UI can render a quote and link to it). Empty when not a reply.
    std::string replyTo;

    // For the call.* content types, the call this signal belongs to. The UI uses
    // it to accept/decline an incoming call.invite and to match later signals.
    std::string callId;

    // Inline keyboard (content types may attach one), as its JSON wire form so
    // a UI can render it without a C++ parser. Empty when there is no keyboard.
    std::string keyboardJson;
    // For contentType == "bot.command": the command name and its raw argument
    // string. For contentType == "bot.callback": the button's callback data.
    std::string commandName;
    std::string commandArgs;
    std::string callbackData;

    // Attachment (content types "file"/"photo"/"audio"/"voice"): a
    // content-store reference and the key to decrypt it. attachmentRef is
    // empty when there is no attachment.
    std::string attachmentRef;
    std::string attachmentName;
    std::string attachmentMime;
    std::uint64_t attachmentSize = 0;
    // For a voice message, how long it plays.
    std::int64_t attachmentDurationMs = 0;

    // For the "avatar"/"device.avatar" content types: the raw avatar image bytes
    // (already decoded from base64), so the UI can hand them to its avatar store
    // without a chat bubble. Empty for every other type.
    std::string avatarData;
};

// The stateful client session: a user identity plus contact and admission
// A file this client announced in a message it sent. The bytes were never
// uploaded anywhere, so serving a later request means reading this path again -
// which is also why the sender can "unsend" simply by forgetting it.
struct SentFile {
    std::filesystem::path path;
    std::string sha256;  // plaintext digest, as announced in the message
    std::uint64_t size = 0;
    // Who this file was announced to. A transfer is served to that contact and
    // nobody else: without this, anyone who learned an id could ask for the
    // bytes, and the sender would encrypt and publish a destination for them.
    std::string peer;
};

// What a direct transfer is doing, so the message block can show it honestly
// instead of pretending the file is already delivered.
enum class TransferState {
    eRequested,  // we asked; waiting for the sender to come up
    eRunning,
    eDone,
    eFailed,
};

struct TransferEvent {
    std::string e2eId;
    // Whose transfer this is. Carried so the view can keep a transfer's state
    // while the user is looking at another conversation, or none.
    std::string peer;
    TransferState state = TransferState::eRequested;
    std::uint64_t bytes = 0;
    std::uint64_t total = 0;
    std::string error;  // set when state == eFailed
    // What this side is doing right now, in the user's words. A direct transfer
    // spends most of its time before the first byte - asking, building a one-time
    // address, publishing it - and a single "connecting" for all of it is what
    // makes a working transfer look stuck.
    std::string stage;
};

using TransferEventFn = std::function<void(const TransferEvent&)>;

// bookkeeping persisted under an account directory, layered over the stateless
// Client API wrappers. This is the logic a GUI or CLI front-end drives.
//
// Admission model: to let a peer write to us we register the handle of their
// delivery pass with our own server and hand them the pass itself; to write to a
// peer we present the pass they gave us. A pass does not expire and is not
// spent, so there is one per correspondent and every device of ours presents the
// same one. Contact bootstrap exchanges both directions over a tokenless contact
// request and its reply.
class Session {
public:
    // Creates a fresh identity and sealing key under accountFile, with no server
    // connection yet. A non-empty passphrase encrypts the private key PEMs at
    // rest (AES-256-CBC); name is a human label stored in the clear for the
    // account picker. Use connectServer() + subscribe() to attach a server.
    static Session create(const std::filesystem::path& accountFile,
        const std::string& passphrase = {}, const std::string& name = {});
    // Creates an account already bound to a server (convenience for the CLI and
    // tests): equivalent to create() followed by connectServer().
    static Session create(const std::filesystem::path& accountFile, const ServerEndpoint& endpoint,
        const std::string& passphrase);
    // Opens an existing session. The passphrase is required when the keys
    // were created encrypted; it is ignored for unencrypted keys.
    static Session open(const std::filesystem::path& accountFile, const std::string& passphrase = {});

    // Binds the account to a serving server (or changes it). Rebinds the
    // transport to the new endpoint and persists it; subscribe() afterwards.
    void connectServer(const ServerEndpoint& endpoint);
    // Whether a serving server is configured (a non-empty host).
    bool isConnected() const;
    const ServerEndpoint& endpoint() const;
    // The facade the transport is currently using, as a URL (for the GUI status).
    std::string activeFacadeUrl() const;
    // The configured facade URLs (the failover list, or the single facade).
    std::vector<std::string> facadeUrls() const;

    // Changes the passphrase this account is kept under. Only the key beside the
    // database is re-sealed, so nothing that is open on it has to be closed; an
    // empty passphrase leaves the account unencrypted at rest.
    void changePassphrase(const std::string& passphrase);

    // Exports the whole session (identity, sealing key, routing meta and
    // contacts) into a single password-encrypted file (CMS PWRI). The bundle
    // holds the keys in plain PEM internally - the password protects the file.
    // Each conversation's pass is copied into the bundle and stays here too: a
    // pass is not spent, so a restored device can write from its first sync.
    void exportAccount(const std::filesystem::path& outFile, const std::string& password);
    // Imports an exported bundle into a fresh accountFile. A non-empty
    // atRestPassphrase re-encrypts the imported keys on disk.
    static void importAccount(const std::filesystem::path& bundleFile,
        const std::filesystem::path& accountFile, const std::string& password,
        const std::string& atRestPassphrase = {});

    std::string fingerprint() const;
    std::string sealingPublicB64() const;
    // The human label set at creation (may be empty).
    const std::string& displayName() const;
    // Changes the account's own display name. Local only: it rewrites the account
    // meta and so the name carried in future invite descriptors (inviteUri), but it
    // is NEVER sent to contacts - each contact controls the name they keep for us.
    void setDisplayName(const std::string& name);

    // The user's own avatar (raw, already-compressed PNG/JPEG bytes) and its
    // mime type; both empty when no avatar is set.
    const Bytes& avatar() const;
    const std::string& avatarMime() const;
    // Sets the user's own avatar. The bytes must already be compressed by the UI
    // to a square image within the protocol cap (500 KB). Persists it, pushes it
    // to every established contact (best effort, no error surfaced) and self-syncs
    // it to the account's other devices. Throws if the data exceeds the cap.
    void setAvatar(const Bytes& data, const std::string& mime);

    // A contact's local display name (empty when unnamed) and its avatar bytes.
    std::string contactDisplayName(const std::string& peerFingerprint) const;
    Bytes contactAvatar(const std::string& peerFingerprint) const;
    // Whether this contact sent us a request we have not yet accepted (we hold
    // their pass but have not issued ours). Drives the "Agree" affordance.
    bool contactIsPending(const std::string& peerFingerprint) const;
    // Whether an acceptance for this contact is in the air: agreed to here, not
    // yet confirmed by the peer's server. Still pending, and not to be agreed to
    // twice while it is.
    bool contactAcceptInFlight(const std::string& peerFingerprint) const;
    // Renames a contact locally and mirrors the change to the account's other
    // devices (a device.contact-name self-message). No-op for an unknown contact.
    void renameContact(const std::string& peerFingerprint, const std::string& name);

    // Mirrors a chat pin/unpin to the account's other devices (a device.chat-pin
    // self-message). The pin list itself lives in the GUI's local store; this only
    // broadcasts the change so every device keeps the same pinned chats.
    void syncChatPinToSelf(const std::string& peerFingerprint, bool pinned);
    // Tells this account's other devices that this conversation has been read
    // through the message sent at this moment. The moment is the sender's own
    // stamp, which is the same on every device - a local row id is not.
    void syncReadToSelf(const std::string& peerFingerprint, std::int64_t sentAtMs);
    // Tells the account's other devices that this conversation was emptied here -
    // our own copy of it, not the correspondent's.
    void syncChatClearToSelf(const std::string& peerFingerprint);
    // Hands the account's own answers to its other devices.
    void syncAccountPrefsToSelf();

    // Permanently removes a contact: drops it from the contact list, deletes its sealed
    // avatar blob, and persists. Local only and irreversible - the peer is not
    // told. No-op for an unknown contact. The caller wipes the local transcript.
    void removeContact(const std::string& peerFingerprint);
    // The same, and the rest of what removing means: the pass this account
    // issued to them are revoked at our server, so what they still hold stops
    // working, and the account's other devices are told to drop them too.
    void removeContactEverywhere(const std::string& peerFingerprint);

    // --- Saved messages ---
    //
    // A chat with ourselves, on every device of this account. Its peer is our own
    // fingerprint, which no contact can ever hold, so nothing can impersonate it.
    bool isSavedChat(const std::string& peerFingerprint) const;
    // Empties it here and on every other device.
    void clearSaved();

    // --- Blocking ---
    //
    // A blocked correspondent's mail and contact requests are dropped as they are
    // read, their pass is revoked, and the block reaches the account's other
    // devices. The conversation is left alone: deleting it is its own action.
    bool isBlocked(const std::string& peerFingerprint) const;
    std::vector<std::string> blockedPeers() const;
    void setBlocked(const std::string& peerFingerprint, bool blocked);

    // --- Per-contact switches ---
    bool contactNotifications(const std::string& peerFingerprint) const;
    bool contactCalls(const std::string& peerFingerprint) const;
    void setContactNotifications(const std::string& peerFingerprint, bool on);
    void setContactCalls(const std::string& peerFingerprint, bool allowed);

    // Whether this account takes incoming calls at all. Off, an invitation is
    // answered with a refusal the moment it arrives - the caller learns it now
    // rather than ringing into nothing. Persisted with the account; on by default.
    bool acceptCalls() const { return acceptCalls_; }
    void setAcceptCalls(bool accept);

    // Whether reading a message tells its sender so (the green tick). Off, the
    // unread bookkeeping here is unchanged - only the correspondent is not told.
    // An account-wide answer like the one above: a correspondent sees one account,
    // not a set of devices, so it is persisted and mirrored to all of them.
    bool sendReceipts() const { return sendReceipts_; }
    void setSendReceipts(bool on);

    // Redeems the portal registration on the configured server and registers
    // this client ID. Mints this account's own I2P destination if it has none
    // and publishes the routing (see publishRouting), so the contact card is
    // reachable as soon as the destination's tunnels are up. The account has no
    // term: it lives while the destination stays delegated.
    void registerAccount();

    // Registers with a server this same process serves. The destination is the
    // server's to raise and it already holds the key, so there is nothing to
    // delegate and no transient to issue - which is also what lets such a daemon
    // run over a transport that cannot issue one at all.
    void registerSelfHosted();

    // Hands the serving server a fresh transient for this account's destination
    // and re-issues the contact card with the routing folded in, inside the term
    // already held (so it grants nothing and consumes no registration grant).
    // Called by subscribe; call it again after a moderated server approves the
    // account, which is the one case where subscribe leaves routing unpublished.
    // Raises ApiError(eAccountPendingApproval) while approval is outstanding.
    void publishRouting();

    // --- Pictures ---
    //
    // A picture that has arrived (or one being sent) lives in the account
    // database like everything else this client keeps: encrypted at rest, gone
    // when the account is deleted, and never a plaintext copy sitting in a cache
    // directory. It is small by construction - the composer shrinks it before
    // sending - so it costs the database little.

    // A voice message: Opus frames, small enough to ride inside the message, kept
    // in the account like a picture.
    bool sendVoice(const std::string& peerFingerprint, const Bytes& opus, std::int64_t durationMs,
        const std::string& e2eId = {},
        const DeliveryWatch& watch = {},
        const std::string& replyTo = {}, bool forwarded = false);

    // Stores a picture's bytes against the message that announced it.
    void putPicture(const std::string& e2eId, const Bytes& bytes);
    // The picture of a message, or nothing when this account does not hold it.
    std::optional<Bytes> picture(const std::string& e2eId) const;
    bool hasPicture(const std::string& e2eId) const;
    // The same for a voice message's audio.
    void putVoice(const std::string& e2eId, const Bytes& bytes);
    std::optional<Bytes> voice(const std::string& e2eId) const;

    // The devices registered on this account, and dropping one. A device that is
    // gone for good keeps every message in the mailbox until the server's
    // retention window expires, because deletion waits for all of them - so its
    // owner has to be able to see the list and end one.
    std::vector<Client::DeviceEntry> devices();
    void retireDevice(const std::string& clientId);
    // Retires this device: the server stops holding mail for it and drops the
    // queue it has. What the account is on the server is untouched - this is the
    // "leave this device" half of leaving, without ending the account.
    void retireThisDevice();
    // Ends this account on its server: the destination is revoked, the mailbox
    // and everything else held for it is dropped, and the registration is gone.
    // Throws when the server refused or could not be reached - the profile it
    // was asked from holds the only key that can ask again, so a caller must not
    // delete that on a failure.
    void closeAccountOnServer();

    // The serving server's onboarding info (message + registration links),
    // shown when a connect/subscribe is refused because this key is not
    // registered yet. Requires a configured server (facades).
    PortalInfo serverPortalInfo();

    // This account's own I2P destination - every account has one, it is how the
    // account is reachable at all.
    // ensureI2pDestination mints the permanent ("master") key the first time
    // and persists it sealed at rest, returning the stable base32 address;
    // subsequent calls are idempotent. The master never leaves the client.
    std::string ensureI2pDestination();
    // Adopts an existing user-owned master from a .dat the user already holds
    // (validated as an unencrypted Ed25519 destination), persisting it sealed at
    // rest and returning its base32. Throws if the account already has a master
    // (a different key would change the user's address) or the blob is invalid.
    std::string loadI2pDestination(const Bytes& privateKeysDat);
    bool hasI2pDestination() const;
    // The stable base32 address (without the ".b32.i2p" suffix), or empty.
    std::string i2pAddress() const;
    // Permanently removes the user-owned master (and any transient) from this
    // account. The deleted key is gone for good; publishing again later would
    // mint a fresh, different address.
    void deleteI2pDestination();

    // Revokes the destination server-side (an empty delegation): the server
    // tears it down and holds nothing. The master stays in the account, so
    // publishRouting later restores the same address.
    void disableI2pDest();
    // The per-user i2p-dest status from the server (for display and decisions).
    I2pDestStatus i2pDestStatus();

    // What the serving server last said about this account's approval. A
    // moderated server carries a registered account without serving it, and the
    // difference is invisible from the client's own state: it is connected, its
    // key is fine, and nothing reaches anybody. Every status poll and every
    // refused publish records the answer here so the UI can say which it is.
    struct ApprovalState {
        bool pending = false;
        // What the operator tells a user still waiting (empty if they wrote none).
        std::string message;
    };
    ApprovalState approvalState() const { return approval_; }
    // The user's own storage usage on the mailbox + blob backends (used/quota each),
    // for the per-account settings view. Best effort - never throws.
    StorageUsage storageUsage();
    // Keeps the personal destination's transient fresh: polls the server status,
    // and if the option is active and the current transient is within
    // leadSeconds of expiry (or absent), issues a fresh transient and uploads it
    // - but only after the poll, so when another of the user's devices has
    // already renewed, this one stands down (the multi-device race). Returns
    // true if it uploaded a new transient. A no-op without a personal dest.
    // The delegation term this account uses, in days, and setting it (which
    // re-issues at once). Bounded by the protocol: kMinDelegationDays ..
    // kMaxDelegationDays.
    std::int64_t delegationDays() const;
    // announce=false applies a term another device chose, without telling them
    // back about it.
    void setDelegationDays(std::int64_t days, bool announce = true);

    bool refreshI2pTransientIfDue(std::int64_t now, std::int64_t leadSeconds);
    // Issues a fresh time-boxed transient (offline keys) from the master, valid
    // until expiresUnix - the delegation handed to the serving server to operate
    // the destination for the subscription window. Throws if the account has no
    // user-owned destination. subscribe() calls this automatically when one
    // exists, for the subscription period.
    void renewI2pTransient(std::int64_t expiresUnix);
    // The active transient blob to hand to the serving server (empty if none).
    Bytes i2pTransient() const;
    // The active transient as I2P-base64 (the form the server feeds its I2P router).
    std::string i2pTransientBase64() const;

    // Sign-in-with-key: signs an opaque challenge issued by a service portal,
    // proving ownership of this identity's key without the key ever reaching
    // the browser. Returns a base64 token the user pastes back into the portal,
    // which verifies it (see verifyLoginBlob) and recovers this fingerprint.
    // Asked when the server serves an address this device has no keys for and no
    // other device answered: (served host, this device's host or empty). The
    // front-end puts the choice to the user and answers with one of the two
    // calls below; until then this account publishes nothing.
    using AddressDecisionFn
        = std::function<void(const std::string& servedHost, const std::string& ourHost)>;
    void onAddressDecision(AddressDecisionFn handler) { addressDecision_ = std::move(handler); }

    // The user chose to serve this device's address (minting one if this device
    // has none). Contacts holding the served address stop reaching this account
    // until they are told the new one.
    void publishThisDeviceAddress();
    // The user chose a clean address: a new master, published as the account's.
    void publishFreshAddress();

    std::string signLogin(const std::string& challenge) const;

    // A signer of this account's own, for a front-end that must not wait for
    // this session's thread to finish what it is doing. It carries a copy of the
    // identity and needs nothing else.
    std::shared_ptr<LoginSigner> loginSigner() const;

    // Asks this account's other devices for the address book. A device that has
    // just been enrolled has no other way to learn a contact: there is no lookup
    // from a fingerprint to a destination, and the capability to read a card is
    // held by the devices that already have it. Answered by every other device
    // that has contacts, in as many messages as the book takes; with no other
    // device the mailbox simply holds the question.
    void askDevicesForContacts();

    // What this account did on the wire, newest last: the connection log the
    // account window shows. Kept in memory only, and small.
    std::vector<WireEvent> connectionLog() const;
    void clearConnectionLog();


    // A bazarish:// invite carrying our full self-verifying serving chain
    // (subscription certificate + server card). A contact can verify it and
    // reach us with no trust in any server. Requires an active subscription.
    std::string inviteUri() const;
    // A shareable descriptor for a contact we already hold: the same artifact as
    // our own invite, built from what they gave us. Passing a contact on is not
    // theirs to consent to, but the routing is already public to anyone they
    // wrote to, and the alternative is retyping a fingerprint that reaches
    // nobody. Throws when we hold no routing for them yet.
    std::string contactInviteUri(const std::string& peerFingerprint) const;
    // Whether this account's own card carries routing (destination + the serving
    // sealing key the server answers card fetches with). False means no invite
    // can be formed yet, however healthy the destination looks server-side.
    bool hasOwnRouting() const;
    // What the messaging server reports about this account's destination: the
    // address it operates and its state ("none" / "building" / "active"). The
    // delegation is what the node holds; this is whether it is actually up.
    DestinationInfo serverDestination();
    // Re-issues our own card inside the term already held, picking up the serving
    // destination and key the server has assigned since the last issue. Cheap
    // (one request, no delegation, no grant) and the repair for a card that was
    // stored before the server had raised the destination.
    void refreshOwnCard();
    // How this account names itself on the destinations it creates, so a router
    // shared by several accounts says whose is whose: the account name, or the
    // head of its fingerprint when it has none.
    std::string destinationOwner() const;

    // Accepts a received contact request: sends a "contact.accept" back, which (as
    // our first reply) carries our descriptor and our pass, so the
    // requester becomes a fully mutual contact and a one-to-one chat opens. A no-op
    // if we cannot reach the requester (no contact / pass) yet.
    void acceptContactRequest(const std::string& peerFingerprint);

    // Adds a contact from an invite descriptor (bazarish://invite?fp&srv&srv_key):
    // the user-signed contact card is fetched for the descriptor's fingerprint
    // and verified against it, then a contact request is sent. Returns the added
    // contact's fingerprint so the UI can surface it for out-of-band verification.
    std::string addByInvite(const std::string& inviteUri, const std::string& text);

    // Adds a contact by username (alias) on the central resolver. The resolver
    // maps the alias to a descriptor over a signed, self-verifying record (chain:
    // record -> delegated key -> hardcoded resolver root); the alias->fingerprint
    // binding is the one residual trust of the name path. Everything after it -
    // the card fetch and its certificates - is verified end-to-end. Returns the
    // resolved fingerprint so the UI can surface it for out-of-band verification
    // (the only defense against a hostile resolver). Throws if no resolver is
    // configured in this build.
    std::string addByUsername(const std::string& alias, const std::string& text);

    // --- Asynchronous contact add ------------------------------------------------
    // addByInvite / addByUsername above are synchronous: they block on a federated
    // card fetch (the serving server dials the peer over I2P, tens of seconds when
    // the peer is slow or unreachable). A GUI must never run that on the thread that
    // also drives sync and the connection, or the whole account freezes until the
    // fetch returns. The three steps below split it so the slow fetch runs off the
    // worker thread on its own transport, and only the fast finalize touches the
    // session - keeping the connection live throughout.

    // What resolveContactCard needs, snapshotted from the live session so the
    // (background) resolve depends on nothing the session may mutate or free.
    struct ContactFetchContext {
        std::string identityPem;        // unencrypted in-memory private PEM
        std::string clientId;
        ServerEndpoint endpoint;
        std::filesystem::path i2pDataDir;
        ResolverCoordinate resolver;
        bool i2pEnabled = false;
        bazarish::i2p::Privacy blobFetchPrivacy = bazarish::i2p::Privacy::eMax;
        std::string destinationOwner;   // account name, for the router status view
        Bytes servingSealingKeyDer;     // what a session secret is sealed to
    };
    // An add to resolve: an invite URI (byUsername=false) or an alias.
    struct ContactCardRequest {
        bool byUsername = false;
        std::string uriOrAlias;
        std::string introText;
        // Names the request itself, so the same one sent again is recognised by
        // the recipient's server as the same delivery rather than stored twice.
        // Empty means a fresh one is drawn when the request is built.
        std::string requestId;
    };

    // An add this account started and has not finished. Written before the work
    // begins and dropped when it ends, so closing the client in the middle of one
    // loses the operation and not the intent.
    struct PendingContactAdd {
        std::string opId;
        ContactCardRequest request;
    };
    std::vector<PendingContactAdd> pendingContactAdds() const;
    void notePendingContactAdd(const PendingContactAdd& pending);
    void forgetPendingContactAdd(const std::string& opId);
    // The outcome of an off-thread resolve, finalized by commitContactAdd. On
    // failure ok is false and error carries a human-readable reason (no throw).
    struct ContactCardResolved {
        bool ok = false;
        std::string error;
        std::string fingerprint;
        ContactInfo info;
        std::string displayName;
        std::string introText;
        // The capability from the descriptor this was resolved from.
        std::string view;
        // Carried from the request, so a resolve that is finished after a restart
        // sends the same request rather than a second one.
        std::string requestId;
    };

    // [worker thread] Snapshot the transport context for an off-thread resolve.
    ContactFetchContext contactFetchContext() const;
    // [any thread] Resolve and verify a contact card using a PRIVATE throwaway
    // transport (its own connection, so it never contends with the session's sync
    // transport). Touches no session state; never throws.
    // Holds a request open on the server's event face until something arrives for
    // this account (or the wait passes), then returns whether anything is
    // pending. Static and context-based like resolveContactCard: it runs on its
    // own connection so a long wait never blocks the session's own transport.
    // Throws when the server has no event face, so the caller can go back to
    // polling.
    // The client the waiter loop keeps: built once, because every Client raises an
    // outbound I2P destination of its own, and rebuilding it per wait left a
    // trail of half-built dialers in the router.
    static std::unique_ptr<Client> makeEventClient(const ContactFetchContext& context);
    static bool waitForEvents(Client& waiter, int waitSeconds);

    static ContactCardResolved resolveContactCard(
        const ContactFetchContext& context, const ContactCardRequest& request);
    // [worker thread] Finalize a resolved add: send the contact request and record
    // the contact. Returns the contact fingerprint. Throws on a delivery failure.
    std::string commitContactAdd(const ContactCardResolved& resolved);

    // Overrides the central resolver coordinate (root fingerprint + destination +
    // serving key). The shipped client bakes one in (defaultResolverCoordinate);
    // this exists for deployments that point at a different resolver and for tests.
    void setResolverCoordinate(ResolverCoordinate coordinate);

    // Emits, as JSON, the artifacts the central resolver's portal needs to claim
    // <alias> for this identity: the normalized name, this user's serving
    // destination + sealing key, and a user-signed alias certificate. The buy is
    // driven by POSTing this to the resolver's /portal/buy; the signing key never
    // leaves the client. Throws if the user has no serving destination yet.
    std::string aliasBuyArtifacts(const std::string& alias) const;

    // Sends an E2E-encrypted message to an established contact, presenting the
    // pass they issued to us. Throws if the contact is unknown or has none.
    // When the peer holds no pass of ours yet (the first reply), ours is
    // registered and attached.
    // e2eId, when given, is used as the protocol message id (so a delivery
    // receipt can be matched back). onAcceptedByOwnServer fires once when our
    // own server has accepted the envelope into its buffer (the "grey" state).
    // Returns true if the recipient server confirmed storage within the poll
    // window (the "yellow" state), false if it was accepted but is still being
    // delivered in the background (stays grey until a read receipt confirms it).
    // replyTo, when set, is the protocol id of the message this one replies to;
    // it rides in the envelope so the recipient can render a quote and link to
    // the original (a no-op reference if they do not hold it locally).
    bool sendMessage(const std::string& peerFingerprint, const std::string& text,
        const std::string& e2eId = {},
        const DeliveryWatch& watch = {}, const std::string& replyTo = {},
        bool forwarded = false);

    // Announces a file as a "file" content message: name, size and digest only.
    // The bytes never leave this machine until the recipient asks for them, so
    // the send itself is instant regardless of file size - and the file must
    // still be at this path, and this client online, when they do.
    bool sendFile(const std::string& peerFingerprint, const std::filesystem::path& path,
        const std::string& e2eId = {},
        const DeliveryWatch& watch = {}, const std::string& replyTo = {});

    // The same transfer, announced as a picture: a message whose point is that
    // it is shown. The recipient fetches it without being asked and draws it;
    // what it never becomes is a file card with a Save button.
    bool sendPicture(const std::string& peerFingerprint, const std::filesystem::path& path,
        const std::string& e2eId = {},
        const DeliveryWatch& watch = {},
        const std::string& replyTo = {});

    // Sends an interactive message: a "text" content message carrying an inline
    // keyboard the recipient can tap to send a bot.callback / bot.command back.
    void sendInteractive(const std::string& peerFingerprint, const std::string& text,
        const InlineKeyboard& keyboard, const std::string& e2eId = {},
        const DeliveryWatch& watch = {});

    // Sends a command invocation (content type "bot.command") to a peer: a bot
    // dispatches on the command name. args is the raw argument string.
    void sendCommand(const std::string& peerFingerprint, const std::string& command,
        const std::string& args = {}, const std::string& e2eId = {},
        const DeliveryWatch& watch = {});

    // Sends a button-press callback (content type "bot.callback") to a peer:
    // data is the tapped button's payload, refMessageId the keyboard message it
    // belongs to (so the bot can correlate the press to a prior message).
    void sendCallback(const std::string& peerFingerprint, const std::string& data,
        const std::string& refMessageId = {});

    // Edits a previously sent message in place (content type "edit"): the peer
    // replaces the message whose id is refMessageId with this text and keyboard
    // (an empty keyboard removes any buttons). Both a bot updating its own
    // keyboard message on a callback and a user revising their own line use
    // this. A client applies it only to a message the sender actually sent.
    // Delivery is tracked like a normal send (the watch and the return value), so
    // the edited message's bubble can reflect the edit's own delivery status
    // instead of the original's.
    bool sendEdit(const std::string& peerFingerprint, const std::string& refMessageId,
        const std::string& text, const InlineKeyboard& keyboard = {},
        const DeliveryWatch& watch = {});

    // Deletes a previously sent message for everyone (content type "delete"): the
    // peer removes the message whose id is refMessageId from its transcript, with
    // no tombstone left behind. Scoped on the receiver to a message the sender
    // actually sent, exactly like an edit.
    void sendDelete(const std::string& peerFingerprint, const std::string& refMessageId);

    // Rotates the serving sealing key our server holds and the capability that
    // reads our card, then hands the new pair to every contact. Nothing is in
    // force until the server acks the commit, so a failure anywhere before that
    // leaves the account exactly as it was; a failure after it leaves contacts
    // to learn the new key from the next message we send them. onStage reports
    // each step so a user watching the dialog can see where it got to.
    void rotateServingKey(const std::function<void(const std::string& stage)>& onStage);

    // How a routing push went: contacts told, and contacts that could not be
    // reached (no capacity, or their server did not answer) - they learn it from
    // the next message that reaches them.
    struct RoutingPushResult {
        std::size_t told = 0;
        std::size_t failed = 0;
    };
    // Whether this contact has told us their invite may not be passed on.
    bool contactSharingRefused(const std::string& peerFingerprint) const
    {
        const auto found = contacts_.find(peerFingerprint);
        return found != contacts_.end() && found->second.sharingRefused;
    }

    RoutingPushResult pushRoutingToContacts(
        const std::function<void(const std::string& stage)>& onStage);

    // Whether contacts are handed our card-read capability, which is what lets
    // them pass us on to someone else. Off, they get an empty one and their
    // client says sharing is not allowed. Persisted with the account.
    bool sharingAllowed() const { return sharingAllowed_; }
    void setSharingAllowed(bool allowed);

private:
    // The capability as contacts get it: ours, or nothing when sharing is off.
    std::string sharedView() const { return sharingAllowed_ ? view_ : std::string(); }

public:

    // Sends a delivery receipt (content type "receipt") acknowledging that we
    // received the message with id refMessageId.
    void sendReceipt(const std::string& peerFingerprint, const std::string& refMessageId);

    // Sets our reaction (an emoji) to a one-to-one message: content type "reaction"
    // referencing refMessageId. An empty emoji removes our reaction. One reaction per
    // user per message - a new one overwrites the old at the recipient.
    void sendReaction(const std::string& peerFingerprint, const std::string& refMessageId,
        const std::string& emoji);

    // Asks the peer to clear the whole conversation with us (content type
    // "chat.clear"): on receipt their client wipes its transcript with us, the
    // same way it auto-applies a delete-for-everyone.
    void sendChatClear(const std::string& peerFingerprint);

    // Whether this device holds the pass that admits it to a contact's mailbox.
    // Nothing runs it down, so this is a yes or no rather than a count.
    bool canWriteTo(const std::string& peerFingerprint) const;

    // What this account names one envelope to a mailbox: keyed with its own seed
    // and bound to the mailbox, so the same message keeps its name on a resend and
    // the copies in two different mailboxes cannot be matched to each other. Pure:
    // the same account always answers the same way, including after a restore.
    std::string deliveryIdFor(const std::string& e2eId, const std::string& mailbox) const;

    // Asks the sender of an announced file to serve it, and downloads it to dest
    // when the sealed offer comes back. Returns at once: the transfer runs in the
    // background and reports through the transfer handler, because it depends on
    // the other side being online and can take as long as I2P takes.
    void requestFile(const std::string& peerFingerprint, const std::string& e2eId,
        const std::filesystem::path& dest);

    // Abandons a running or requested transfer: this side stops at once, and the
    // other side is told so it stops its half too - a transfer costs both of them
    // a destination and both of them tunnels, so a stop that ended only one half
    // would leave the other serving nobody until its window ran out.
    void cancelTransfer(const std::string& e2eId);

    // Where transfer progress and outcomes are reported. One handler for the
    // whole session; events carry the message id they belong to.
    void setTransferHandler(TransferEventFn handler);

    // Forgets every file announced to one contact. What a record holds - a path
    // on this machine and who it was offered to - is about a conversation, so it
    // goes when the conversation does.
    void forgetSentFilesFor(const std::string& peerFingerprint);
    // Sender unsend: forgets the file announced for a message we sent, so a later
    // request from the recipient is answered "no longer available". Nothing has
    // to be deleted anywhere else - the bytes were never copied off this machine.
    void unsend(const std::string& e2eId);

    // Overrides the I2P tunnel privacy profile used for direct transfers (both
    // serving and fetching, always over one-time destinations). Unset, transfers
    // follow the process-wide account.
    void setTransferPrivacy(bazarish::i2p::Privacy privacy);

    // Lets go of the I2P destinations this account holds open, tearing down their
    // tunnels. Called when the account goes offline: it is no longer reachable
    // and no longer sending, so keeping tunnels alive only announces to the
    // network that somebody is there. The next request builds a fresh
    // destination. A call in progress keeps its own media destination.
    void releaseI2pLinks();

    // --- Audio calls (client-to-client; signalling over E2E, media over I2P) ---

    // Lifecycle of the single call this session tracks at a time.
    enum class CallState {
        eIdle,
        eOutgoing,  // we invited; awaiting the peer's accept
        eIncoming,  // a call.invite arrived; awaiting our accept/decline
        eActive,    // media is flowing
    };

    // How a finished call ended, for the chat-history record.
    enum class CallOutcome {
        eAnswered,   // connected and hung up normally (durationSec is meaningful)
        eNoAnswer,   // outgoing: the peer never answered before the ring timeout
        eDeclined,   // explicitly rejected (by the peer for our outgoing call, by us
                     // for an incoming one)
        eMissed,     // incoming: we never answered (timeout) or the caller cancelled
        eCancelled,  // outgoing: we hung up before the peer answered
        eBusy,       // outgoing: the peer was already in another call
        eRefused,    // outgoing: the peer does not take calls at all right now
    eRefusedHere,  // incoming: this account does not take calls, or not theirs
    };

    // A finished call awaiting a chat-history entry. Drained by takeCallLog().
    struct CompletedCall {
        std::string peer;
        bool incoming = false;
        CallOutcome outcome = CallOutcome::eMissed;
        std::int64_t durationSec = 0;  // connected duration; 0 unless eAnswered
    };

    // A snapshot of the current call for the UI / CLI.
    struct CallInfo {
        CallState state = CallState::eIdle;
        std::string callId;
        std::string peerFingerprint;
        bool muted = false;
        std::uint64_t packetsSent = 0;
        std::uint64_t packetsReceived = 0;
        // What the caller is waiting on: the invitation being delivered, then the
        // peer answering, then media. Empty once the call is running.
        std::string stage;
        // The peer's device is showing the call and nobody has answered yet.
        bool peerRinging = false;
        // Unix ms when media was proven in both directions; 0 until then.
        std::int64_t connectedAtMs = 0;
        // Loudness in each direction, 0..1: what this microphone hears and what
        // arrives from the peer. Zero while no call is running.
        float inputLevel = 0.0F;
        float outputLevel = 0.0F;
    };

    // Audio device backends are injected so the core stays Qt-free: the GUI sets
    // a Qt Multimedia backend; the CLI and tests fall back to the built-in
    // synthetic backend (a tone source and a counting sink). A factory makes a
    // fresh device per call.
    using AudioSourceFactory = std::function<std::unique_ptr<AudioSource>()>;
    using AudioSinkFactory = std::function<std::unique_ptr<AudioSink>()>;
    // Replaces the transport a card / alias fetch uses. Only a test harness sets
    // this; a running client always uses the direct-I2P one, because a relayed
    // lookup would tell our own server who is being added.
    void setFetchTransport(FetchTransport transport);
    // Replaces the courier outgoing mail is carried by. Only a test harness sets
    // this; a running client always dials the recipient over I2P itself.
    void setOutboundCourier(std::unique_ptr<OutboundCourier> courier);

    void setAudioBackend(AudioSourceFactory sourceFactory, AudioSinkFactory sinkFactory);


    // Places an outgoing audio call to an established contact. STRICT: a working
    // I2P transport is required; without it this throws ApiError(eI2pUnavailable)
    // with a readable message and no call is placed. Builds a one-time I2P
    // datagram destination for the media and sends a call.invite (carrying that
    // destination and a fresh per-call media key) over the E2E content path.
    // Throws if the contact is unknown or a call is already in progress.
    void startAudioCall(const std::string& peerFingerprint);


    // Accepts the pending incoming call (its id must match). STRICT I2P as above:
    // builds our media destination, replies with call.accept and starts media.
    void acceptCall(const std::string& callId);

    // Declines the pending incoming call (sends call.decline) and clears it.
    void declineCall(const std::string& callId);

    // Ends the active or ringing call (sends call.end) and tears down media.
    void endCall();

    // Mutes/unmutes the local microphone while staying connected.
    void setCallMuted(bool muted);


    // The current call snapshot (state eIdle when there is none).
    CallInfo currentCall() const;

    // Drains the calls that finished since the last call - each needs a chat-history
    // entry (incoming/outgoing + how it ended). Empty when nothing finished.
    std::vector<CompletedCall> takeCallLog();
    // Advances the call's ring/answer timeout so a call never rings forever: an
    // unanswered outgoing or incoming call is torn down and queued for takeCallLog()
    // (an outgoing timeout also cancels the peer). Call periodically - the GUI does
    // so on every sync tick; a no-op when there is no ringing call.
    void tickCalls();

    // Pulls and decrypts pending items, applies their contact side effects,
    // and acks items the core consumes itself. autoAckSurfaced (default true) acks a
    // SURFACED item in the loop too - the simple behaviour the CLI and bots want.
    // The GUI passes false so a surfaced item is NOT acked here (it comes back with a
    // non-empty pendingId); the GUI acks it via ackPending only after durably
    // persisting it, so a crash between fetch and store never loses a message.
    // maxItems caps how many mailbox items this pass takes; zero takes them all.
    // A caller whose thread is also the one that starts a call, sends a message
    // and publishes the levels a call window draws asks for a bounded pass: a
    // mailbox with a hundred items in it must not be a minute in which none of
    // that happens. It then comes straight back for the rest.
    std::vector<IncomingMessage> sync(bool autoAckSurfaced = true, std::size_t maxItems = 0);
    // What such a caller passes, and what it asks afterwards. Each item is a
    // fetch over I2P, so a handful is the most a user should ever wait behind.
    static constexpr std::size_t kPendingItemsPerPass = 5;
    // Whether the last pass left items in the mailbox.
    bool morePending() const { return morePending_; }
    // Writes whatever the courier has confirmed since the last call to the
    // account's other devices. A delivery that finished on the courier's own
    // thread leaves its echo here, so a caller that reads its mailbox only when
    // there is mail calls this on its own upkeep - otherwise a quiet account
    // would hold its own sends back from its other devices.
    void flushPendingEchoes();
    // Items surfaced to the caller that it has not acked yet. They stay in the
    // mailbox until it does, so a caller that watches for new mail can tell
    // "the server still holds what I am carrying" from "there is more to take".
    std::size_t awaitingAcks() const { return awaitingAck_.size(); }

    // Acks a pending mailbox item by its server-side blob id (IncomingMessage's
    // pendingId), removing it from the mailbox. Called after the item has been
    // durably persisted on the client side. Throws if the server is unreachable.
    void ackPending(const std::string& pendingId);

    bool hasContact(const std::string& peerFingerprint) const;
    // Fingerprints of all known contacts, for UI listing.
    std::vector<std::string> contactFingerprints() const;


    // Declared here and defined in the .cpp so the account database stays an
    // incomplete type everywhere else; a session is moved, never copied.
    ~Session();
    Session(Session&&) noexcept;
    Session& operator=(Session&&) noexcept;

private:
    Session(std::filesystem::path accountFile, std::unique_ptr<Client> client, Key sealingKey,
        std::map<std::string, Contact> contacts);

    // Persists a subscribe/renew result: the card we just signed and the routing
    // it carries.
    void storeCard(const PublishResult& result);
    // This account's own destination as a routing host, empty without a master.
    std::string ownRoutingHost() const;

    // Seals one device-to-device notice to ourselves and submits it. What every
    // device.* self-message is built on: nothing is presented, no destination is
    // dialled, and only our own devices can read it.
    void sendSelf(nlohmann::json inner);
    // Keeps a message in the saved chat on the account's other devices. The
    // device that saved it already has it.
    bool saveToSelf(nlohmann::json message);
    void persistBlocked();
    void persistPendingRevokes();
    // Asks our server again for every revocation it has not confirmed. Cheap and
    // idempotent, so it runs on every sync until the list is empty.
    void retryPendingRevokes();
    // The pass this account admits one correspondent by. Derived, so nothing is
    // stored and every device of ours arrives at the same value.
    Bytes passIdFor(const std::string& peerFingerprint) const;
    // Registers that pass with our own server, so the correspondent can write to
    // us, and returns it (base64) to hand over. Registering one already held is
    // how a block is lifted.
    std::string registerPassFor(const std::string& peerFingerprint);
    // Asks our own server to drop it. What makes blocking or removing a contact
    // take their write access with it - and the only thing that does, so an
    // unheard answer is remembered and asked again.
    void revokePassFor(const std::string& peerFingerprint);

    // Sends a contact request to a peer whose verified routing info is
    // already known (from a lookup or an invite). Registers our pass
    // and records the contact, adopting displayName as its local label (the
    // alias used or the name carried in the invite) when non-empty.
    // descriptorView is the capability from the descriptor this contact was
    // added by: kept so their invite can be shared on.
    void requestWithInfo(const std::string& requestId, const std::string& peerFingerprint,
        const std::string& text,
        const ContactInfo& info, const std::string& displayName = {},
        const std::string& descriptorView = {});

    // The fetch transport for card / alias-resolve frames: a fresh transient-I2P
    // dial, and only that - a relayed lookup would tell our own server
    // I2P proxy when there is no I2P transport of our own or the direct dial fails. A
    // served negative (CARD_UNKNOWN / ALIAS_UNKNOWN) is authoritative and does
    // not trigger the fallback - only a transport failure does.
    FetchTransport fetchTransport() const;

    // Sends a built inner content envelope to an established contact: handles
    // the first-reply bootstrap, seals to the peer and presents their pass. Returns
    // whether delivery was confirmed within the poll window (see deliver()).
    // waitForOutcome defaults to false: the call returns as soon as the delivery
    // is handed to the courier (the thread that asked is never blocked on a
    // round-trip over I2P), and the watch reports where it got to and how it
    // ended. True runs the whole attempt schedule on the calling thread, for a
    // send whose caller is the one that must answer for it.
    // establishOnFirstReply (default true): on the FIRST content we send to a peer
    // that wrote to us first, attach our bootstrap (routing + our pass)
    // and mark the contact accepted (issuedToThem). A read receipt passes false so
    // it can confirm a read WITHOUT auto-accepting an un-accepted contact request -
    // the request is still accepted explicitly (Agree) or by sending a real message.
    // One line in the connection log, and how a correspondent is named in it:
    // the local name when there is one, and the head of the fingerprint either
    // way - a full one has no business in a window meant to be screenshotted.
    // One contact as the address book carries it, and the two halves of the
    // exchange: an answer to another device of ours, and what to do with one.
    nlohmann::json contactBookEntry(
        const std::string& peerFingerprint, const Contact& contact) const;
    void sendContactBookTo(const std::string& toDevice);
    void applyContactBook(const nlohmann::json& entries);

    // The identity keys this account holds for a correspondent, or an empty pair
    // when it holds none. Its own keys for its own devices.
    IdentityKeys knownKeysFor(const std::string& peerFingerprint) const;
    // Keeps the keys a correspondent introduced themselves with. Once only: a
    // later message may not re-introduce a contact under different keys.
    static void rememberKeys(Contact& contact, const IdentityKeys& keys);

    // One envelope into this account's own mailbox, signed and sealed to itself.
    void submitSignedToSelf(nlohmann::json inner, const std::string& kind) const;

    void noteWire(bool outgoing, std::string what, std::string status, std::string detail) const;
    std::string wireName(const std::string& peerFingerprint) const;

    bool sendContent(const std::string& peerFingerprint, nlohmann::json inner,
        const DeliveryWatch& watch = {}, bool waitForOutcome = false,
        bool establishOnFirstReply = true);

    // Sends the user-owned I2P master to the account's other devices: a
    // service content message ("device.i2p-master") sealed to our own sealing
    // key and delivered tokenlessly to our own destination, so it lands in our
    // own mailbox and every device of this account picks it up on sync and
    // persists the same master (preserving the b32 across devices). Best effort;
    // a no-op when there is no master or our routing is not known yet.
    void syncI2pMasterToSelf();
    // Looks in this account's own mailbox for the address its other devices
    // already use. `wantedHost` narrows it to the one the server serves; empty
    // takes the first this account wrote to itself. Read-only: nothing is acked.
    bool adoptI2pMasterFromOwnMailbox(const std::string& wantedHost = {});
    bool reconcileI2pAddress();
    // Asks the account's other devices for the keys to one address.
    void askDevicesForI2pMaster(const std::string& servedHost);
    // Takes on an address in place of the one this device holds, dropping the
    // delegation signed by the old master with it. Only ever called for the
    // address the server confirms it is serving.
    void replaceI2pMaster(const Bytes& privateKeysDat);
    // Settles which address this account is served on, before anything is
    // published. True when this device can operate it (it already holds the
    // keys, another device handed them over, or the account is new here and this
    // device's address becomes its own). False when the server serves an address
    // nobody answered for: the choice is then the user's, and onAddressDecision
    // has been told about it.

    void syncDelegationTermToSelf();

    // Echoes a message this device just sent to the account's other devices, so
    // the conversation reads the same everywhere. Rides our own mailbox like the
    // other device.* service messages; best effort, and never a chat bubble on
    // the device that sent it.
    void echoSentToSelf(const std::string& peerFingerprint, const nlohmann::json& inner);

    // Pushes our own avatar to a contact as an "avatar" service message, once,
    // when the dialog is mutually established (we have engaged with them) and we
    // can reach them. A no-op (never an error) when we have no avatar, the peer
    // is unreachable, or it was already sent. Gated on issuedToThem so an
    // un-accepted incoming request never triggers an automatic avatar reply.
    // Pushes our avatar to one contact. `removal` is what makes an empty avatar
    // a message rather than nothing to say: it tells a contact that holds the
    // old one to drop it.
    void maybeSendAvatarToContact(const std::string& peerFingerprint, bool removal = false);
    // Sends our own avatar to the account's other devices (a device.avatar
    // self-message), sealed to our own key and delivered to our own destination.
    void syncAvatarToSelf();
    // Mirrors a contact rename to the account's other devices (device.contact-name).
    void syncContactNameToSelf(const std::string& peerFingerprint, const std::string& name);
    // Persists our own avatar bytes (sealed at rest) and records its mime in meta.
    void storeOwnAvatar(const Bytes& data, const std::string& mime);
    // Persists a contact's received avatar bytes (sealed at rest) and its mime.
    void storeContactAvatar(
        const std::string& peerFingerprint, const Bytes& data, const std::string& mime);
    // Writes an account blob, sealed under the passphrase when the account is
    // encrypted (the generic form behind persistI2pBlob, reused for avatars).
    void persistSealedBlob(const std::string& filename, const Bytes& blob) const;

    // --- Call helpers ---

    // Builds the one-time RAW datagram endpoint that carries the call's media (a
    // published encrypted-LS b33 destination on the embedded router, torn down
    // with the call).
    std::shared_ptr<bazarish::i2p::Endpoint> openCallMediaSession();
    // Shared body of startAudioCall: builds the media destination
    // (strict I2P), sends the call.invite
    // and records the outgoing-call state.
    void startCall(const std::string& peerFingerprint);
    // Wires the media engine (transport + audio backend + codec) for the
    // active call against the peer's media destination and starts it.
    void startCallMedia();
    // Stops media, closes the datagram session, and resets to the idle state.
    void clearCall();
    // Sends a call.* signalling content message (E2E, content class) to a peer.
    // Returns whether the peer's server took it (see the call stages).
    // Tells this account's other devices that this one answered or refused the
    // call they are all showing.
    void announceCallTaken(const std::string& callId);
    bool sendCallSignal(
        const std::string& peerFingerprint, const std::string& type, nlohmann::json extra);
    // Dispatches a decrypted call.* signal during sync(), updating call state and
    // starting/stopping media as needed. Returns the content type handled.
    void handleCallSignal(const std::string& type, const std::string& from,
        const nlohmann::json& body, IncomingMessage& message);
    // Queues a chat-history entry for the current call with the given outcome (using
    // its peer, direction and connected time). Call before clearCall().
    void logCompletedCall(CallOutcome outcome);

    // Seals a delivery envelope to the recipient destination's sealing key and
    // hands it to this client's own courier, which dials that destination over
    // I2P. Nothing passes through this account's own server: it is never asked to
    // dial anyone, so it never learns who is written to.
    // waitForOutcome=false returns as soon as the delivery is queued and reports
    // through the watch; true runs the attempt schedule here and returns true when
    // the recipient's server signed for the envelope, throwing when it refused or
    // could not be reached - then the return value is the outcome and the watch's
    // outcome callback is not used.
    // e2eId, when given, is the message this envelope carries: the delivery
    // id is derived from it, so sending the same message again is recognised as
    // the same delivery rather than stored twice. Empty for what carries no
    // message of its own (an ack, a receipt).
    bool deliver(const std::string& toDest, const Key& servingSealingKey,
        const std::string& deliveryClass, const std::string& mailbox,
        const Bytes& pass, const Bytes& payload,
        const DeliveryWatch& watch = {}, bool waitForOutcome = true,
        const std::string& e2eId = {});
    // The courier this account delivers through, built on first use (the router
    // has to be up first). Thread-safe: sends come from the worker thread and
    // from a file transfer's own thread.
    OutboundCourier& outboundCourier();
    void persistContacts() const;
    void persistMeta() const;
    // Serializes the in-memory contacts into the on-disk JSON shape.
    nlohmann::json contactsToJson() const;


    std::filesystem::path accountPath_;
    // The account's storage: one encrypted file holding keys, metadata, contacts
    // and blobs. Opened for the session's lifetime.
    std::unique_ptr<AccountDb> db_;
    // This account's outbound delivery: the destination held for each
    // correspondent, and the workers that carry the envelopes over I2P. Built on
    // the first send, because the router has to be up before either can exist.
    // Held behind a shared pointer because the session is movable and a mutex is
    // not, and because the delivery workers must not have it moved out from under
    // them. The courier is declared last so it stops (joining its workers) before
    // the leases it dials through are destroyed.
    struct Outbound {
        std::mutex mutex;
        std::unique_ptr<OutboundLeases> leases;
        std::unique_ptr<OutboundCourier> courier;
    };
    std::shared_ptr<Outbound> outbound_ = std::make_shared<Outbound>();
    // A peer asked for a file we announced: encrypt it to a temp ciphertext, raise
    // a one-time destination, seal the offer back and serve until the window
    // closes. Runs on its own thread - building tunnels takes tens of seconds.
    // Answers one device's request for a file we announced: a one-time
    // destination of its own, named in the offer so their other devices know it
    // is not for them.
    // Shared by sendFile and sendPicture: the announcement differs only in type.
    bool announceTransfer(const std::string& type, const std::string& peerFingerprint,
        const std::filesystem::path& path, const std::string& e2eId, const DeliveryWatch& watch,
        const std::string& replyTo);

    void serveRequestedFile(const std::string& peerFingerprint, const std::string& fileId,
        const std::string& forAsk);
    // Removes one serve from the registry, but only while it is still the serve
    // that registered it.
    void dropServe(const std::string& serveId, const std::shared_ptr<std::atomic<bool>>& cancel);
    // One half of a transfer that has just been stopped: who was on the other
    // side of it, and which device was pulling the file.
    struct StoppedHalf {
        std::string peer;
        // Which request this half belongs to, by the name that request drew for
        // itself. Not a device id: naming the device would tell a correspondent
        // which of this account's devices is pulling a file, and over a few
        // transfers how many there are.
        std::string ask;
    };
    // Stops every part of one transfer this device runs - the fetch we asked for
    // and each serve of the same file - and reports it as stopped. fromPeer, when
    // set, limits it to that contact (a stop that arrived over the wire may not
    // Whether one of this device's own file requests is called this. What tells
    // an offer meant for this device from one meant for another of ours, now
    // that the request names itself rather than the device behind it.
    bool awaitingAsk(const std::string& ask) const;
    // touch anybody else's transfer); forAsk, when set, limits it to the
    // device that asked for the file. Returns what was stopped, so the caller can
    // tell the other side.
    std::vector<StoppedHalf> stopTransfer(const std::string& fileId,
        const std::string& fromPeer = {}, const std::string& forAsk = {});
    // A sealed offer came back for a file we asked for: fetch it. Also threaded.
    void startAnnouncedFetch(const FileOffer& offer, const std::string& peer);
    void emitTransfer(const std::string& e2eId, TransferState state, std::uint64_t bytes,
        std::uint64_t total, const std::string& error = {},
        const std::string& stage = {},
        const std::string& peer = {});
    void loadSentFiles();
    void persistSentFiles() const;

    std::unique_ptr<Client> client_;
    // The central alias resolver this account resolves usernames against.
    ResolverCoordinate resolverCoordinate_ = defaultResolverCoordinate();
    // The account in force for a transfer: the override if one was set, else the
    // process-wide account.
    bazarish::i2p::Privacy transferPrivacy() const;
    std::optional<bazarish::i2p::Privacy> transferPrivacy_;
    // The embedded I2P router is process-global (the i2pd engine allows only one
    // per process), so every account shares the one instance (see sharedI2pRouter).
    // It is started lazily on first transport use, so offline operations and tests
    // that never reach the network pay nothing.
    bazarish::i2p::Router& i2pRouter() const;

    // Injected audio device backends (empty -> the built-in synthetic
    // backend).
    AudioSourceFactory audioSourceFactory_;
    AudioSinkFactory audioSinkFactory_;

    // The single in-flight call. Media objects are non-null only while active.
    struct ActiveCall {
        CallState state = CallState::eIdle;
        std::string callId;
        std::string peerFingerprint;
        std::string peerMediaDest;  // the peer's media datagram routing address
        Bytes mediaKey;             // 32-byte AES-256-GCM key, shared both ways
        bool initiator = false;     // true on the caller side (nonce role prefix)
        bool muted = false;
        std::int64_t startedAtMs = 0;    // invite sent (outgoing) / received (incoming)
        // When media first arrived from the peer - the call'''s real start, and
        // the only moment both sides agree on within a round trip.
        // When the invitation was handed to our server, and when the peer's server
        // took it. Delivery and ringing are different waits with different limits.
        std::int64_t invitedAtMs = 0;
        std::int64_t deliveredAtMs = 0;
        std::string stage;
        // Unix ms when the peer's device confirmed it is showing the call. Until
        // then the invitation is only known to have reached their server.
        std::int64_t peerRingingAtMs = 0;
        std::int64_t connectedAtMs = 0;
        // What the media engine had received when it was last looked at, and
        // when that was: a call whose media has gone quiet has been left.
        std::uint64_t lastPacketsReceived = 0;
        std::int64_t lastPacketAtMs = 0;
        std::shared_ptr<bazarish::i2p::Endpoint> dgram;
        std::unique_ptr<I2pCallTransport> transport;
        std::unique_ptr<CallMedia> media;
    };
    ActiveCall call_;
    // Calls that finished but whose chat-history entry has not been drained yet.
    std::vector<CompletedCall> pendingCallLog_;
    std::map<std::string, SentFile> sentFiles_;
    // Transfers this client is driving, by message id: a pending entry is created
    // by requestFile and consumed when the offer arrives. Held behind a shared
    // pointer because the transfer threads outlive any particular Session object
    // (the session is movable, a mutex is not).
    struct PendingTransfer {
        std::filesystem::path dest;
        std::shared_ptr<std::atomic<bool>> cancel;
        // Who is serving it: stopping on this side has to reach them.
        std::string peer;
        // What this one request is called. Drawn fresh for it, so the offer that
        // comes back can be addressed to the device that asked without the
        // correspondent being told which device that is - a client id is stable,
        // and a contact who exchanged a few files would otherwise learn the set
        // of devices this account writes from.
        std::string ask;
    };
    // One file this side is serving, under the per-device key it was registered
    // with: the flag that stops it, and whose transfer it is. The file's own id
    // is kept beside the key because two devices of one contact pull the same
    // file under two keys, and a stop names the file, not the key.
    struct ServingTransfer {
        std::shared_ptr<std::atomic<bool>> cancel;
        std::string fileId;
        std::string peer;
        std::string forAsk;
    };
    struct TransferRegistry {
        std::mutex mutex;
        std::map<std::string, PendingTransfer> pending;
        std::map<std::string, ServingTransfer> serving;
        TransferEventFn onEvent;
    };
    std::shared_ptr<TransferRegistry> transfers_ = std::make_shared<TransferRegistry>();
    Key sealingKey_;
    // Secret behind deliveryIdFor: drawn once when the account is created, carried
    // through backup and restore, and never changed - every envelope the account
    // has sent is named under it. Never leaves the account.
    std::string deliveryIdSeed_;
    // Set by sync(): the mailbox held more than one pass takes, and what is left
    // is work rather than items already in somebody's hands.
    bool morePending_ = false;
    // Calls this session has already seen the end of, newest last. An invitation
    // and the word that the call is over are two mailbox items, and nothing
    // promises they arrive in that order: without this, an invite fetched after
    // its own ending rings for a call that is long finished.
    std::deque<std::string> endedCalls_;
    // Items handed out for the caller to store, whose ack has not come back yet.
    // A bounded pass would otherwise fetch the same five items over and over: the
    // ack travels back through the caller and lands after the next pass has
    // already asked for them.
    std::set<std::string> awaitingAck_;
    // Secret behind every delivery mask: drawn once when the account is created,
    // carried through backup and restore, and never sent - only masks derived
    // from it are, and only to this account's own server.
    Bytes deliverySecret_;
    std::map<std::string, Contact> contacts_;
    // Correspondents whose mail is dropped as it is read. Kept apart from the
    // contacts so a block outlives the contact it was made on.
    std::set<std::string> blocked_;
    // Pass handles (base64) our server has not confirmed dropping. Kept here
    // rather than on the contact, because removing a contact is one of the two
    // things that revokes, and a flag on a record being deleted would go with
    // it - leaving a correspondent writing to a mailbox that thinks it cut them
    // off. Persisted: an unconfirmed revocation must outlive the process.
    std::set<std::string> pendingPassRevokes_;
    // The devices of this account that have already asked the others for the
    // address book; each device asks once.
    std::vector<std::string> contactsAskedBy_;
    // Our own serving destination + serving sealing key (SPKI DER, base64),
    // learned on subscribe (GET /v1/messaging/destination) and forwarded to
    // contacts in the E2E bootstrap so they route and seal replies to us.
    std::string myDest_;
    std::string myServingKeyB64_;
    // The capability our server issued for reading our card: what an invite
    // carries so a contact can fetch it, and nothing else.
    std::string view_;
    // How long this account delegates its destination for, in days. The user
    // picks it inside the protocol's ceiling: shorter means leaving a server
    // takes effect sooner, longer means an absent client stays reachable.
    std::int64_t delegationDays_ = kDefaultDelegationDays;
    // Set only by a test harness (see setFetchTransport).
    FetchTransport fetchTransportOverride_;
    // Human label for the account picker (stored in the clear in meta.json).
    std::string name_;
    // The user's own avatar (compressed PNG/JPEG bytes) and its mime. The bytes
    // live in a sealed account file; the mime is recorded in meta.json. Empty
    // when no avatar is set.
    Bytes avatar_;
    std::string avatarMime_;
    // Our own subscription certificate (DER, base64), retained on subscribe
    // so we can publish the full self-verifying chain in an invite.
    std::string cardB64_;
    // The last word from the server on whether this account is served yet.
    ApprovalState approval_;
    // Whether the private key PEMs are encrypted at rest. Persisted in meta so
    // open() knows to require a passphrase.
    bool encrypted_ = false;
    // Whether our capability travels to contacts (see sharingAllowed).
    bool sharingAllowed_ = true;
    // Incoming calls are taken unless the user says otherwise; see acceptCalls().
    bool acceptCalls_ = true;
    bool sendReceipts_ = true;
    // The at-rest passphrase, retained for the session lifetime so contacts can
    // be re-sealed on every change. Empty when the
    // account is unencrypted.
    std::string passphrase_;
    // This account's own I2P destination, empty until it is minted (subscribing
    // mints one). The master private key (i2p-master.dat) is the user's
    // long-term routing identity; the active
    // transient (i2p-transient.dat) is the time-boxed delegation for the
    // current serving server. Both are sealed at rest when the account is
    // encrypted.
    // Echoes waiting for this account's own thread: a send the recipient's server
    // signed for, reported on the courier's thread and written to our own mailbox
    // here. Held behind a pointer because a session moves and a delivery in
    // flight must not be left holding the address it moved from.
    struct EchoQueue {
        std::mutex mutex;
        std::vector<std::pair<std::string, nlohmann::json>> pending;
        // Acceptances whose bootstrap the peer's server confirmed it stored, and
        // ones it never took. Both are decided on the courier's thread and
        // applied on the session's, which is the only one that may touch the
        // contact book.
        std::vector<std::string> established;
        std::vector<std::string> notEstablished;
    };
    std::shared_ptr<EchoQueue> echoQueue_ = std::make_shared<EchoQueue>();
    AddressDecisionFn addressDecision_;
    Bytes i2pMaster_;
    std::string i2pAddress_;
    Bytes i2pTransient_;

    // Writes an I2P key blob, sealed under the passphrase when encrypted.
    void persistI2pBlob(const std::string& filename, const Bytes& blob) const;
};

}  // namespace bazarish::client
