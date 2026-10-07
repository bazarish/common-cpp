// Bazarish project (c) 2026
#pragma once

#include "LoginSigner.hpp"

#include "AudioIo.hpp"
#include "CallMedia.hpp"
#include "Authorship.hpp"
#include "Client.hpp"
#include "FileTransfer.hpp"
#include "OutboundLeases.hpp"

#include <bazarish/AliasMaintenance.hpp>
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

struct DeliveryWatch {
    OutboundCourier::PhaseFn onPhase;
    OutboundCourier::OutcomeFn onOutcome;
};

struct InlineButton {
    std::string text;
    std::string data;
    std::string command;
};

using InlineKeyboard = std::vector<std::vector<InlineButton>>;

std::string inlineKeyboardJson(const InlineKeyboard& keyboard);

inline constexpr char kSavedChatName[] = "Saved messages";
inline constexpr char kContactNamePrefix[] = "(Contact) ";

std::string safeContactName(const std::string& proposed);

struct Contact {
    std::string sealingPublicB64;
    std::string dest;
    std::string servingSealingB64;
    std::string view;
    bool sharingRefused = false;
    std::string sendPass;
    bool issuedToThem = false;
    bool acceptInFlight = false;
    std::string displayName;
    std::string identityClassicalB64;
    std::string identityPqB64;
    Bytes avatar;
    std::string avatarMime;
    bool avatarSentToPeer = false;
    bool notifications = true;
    bool allowCalls = true;
};

struct IncomingMessage {
    std::string contentType;
    std::string fromFingerprint;
    std::string text;
    std::string deliveryClass;
    bool sentByUs = false;
    bool establishedContact = false;
    std::string rawType;
    std::string e2eId;
    bool forwarded = false;
    std::string pendingId;
    std::int64_t sentAt = 0;
    std::string refId;

    std::string replyTo;

    std::string callId;

    std::string keyboardJson;
    std::string commandName;
    std::string commandArgs;
    std::string callbackData;

    std::string attachmentRef;
    std::string attachmentName;
    std::string attachmentMime;
    std::uint64_t attachmentSize = 0;
    std::int64_t attachmentDurationMs = 0;

    std::string avatarData;
};

struct SentFile {
    std::filesystem::path path;
    std::string sha256;
    std::uint64_t size = 0;
    std::string peer;
};

enum class TransferState {
    eRequested,
    eRunning,
    eDone,
    eFailed,
};

struct TransferEvent {
    std::string e2eId;
    std::string peer;
    TransferState state = TransferState::eRequested;
    std::uint64_t bytes = 0;
    std::uint64_t total = 0;
    std::string error;
    std::string stage;
};

using TransferEventFn = std::function<void(const TransferEvent&)>;

class Session {
public:
    static Session create(const std::filesystem::path& accountFile,
        const std::string& passphrase = {}, const std::string& name = {});
    static Session create(const std::filesystem::path& accountFile, const ServerEndpoint& endpoint,
        const std::string& passphrase);
    static Session open(const std::filesystem::path& accountFile, const std::string& passphrase = {});

    void connectServer(const ServerEndpoint& endpoint);
    bool isConnected() const;
    const ServerEndpoint& endpoint() const;
    std::string activeFacadeUrl() const;
    std::vector<std::string> facadeUrls() const;

    void changePassphrase(const std::string& passphrase);

    struct PairingOffer {
        std::string uri;
        std::string code;
    };

    enum class PairingStage {
        ePublishing,
        eWaiting,
        eWrongCode,
        eSending,
        eDone,
        eRefused,
        eFailed,
    };

    struct PairingEvent {
        PairingStage stage = PairingStage::ePublishing;
        std::uint64_t done = 0;
        std::uint64_t total = 0;
        int wrongCodes = 0;
        std::string error;
    };

    using PairingEventFn = std::function<void(const PairingEvent&)>;

    PairingOffer startPairing(PairingEventFn onEvent);
    void stopPairing();

    Bytes exportAccountBytes(const std::string& password);
    void exportAccount(const std::filesystem::path& outFile, const std::string& password);
    static void importAccountBytes(const Bytes& bundle,
        const std::filesystem::path& accountFile, const std::string& password,
        const std::string& atRestPassphrase = {});
    static void importAccount(const std::filesystem::path& bundleFile,
        const std::filesystem::path& accountFile, const std::string& password,
        const std::string& atRestPassphrase = {});

    std::string fingerprint() const;
    std::string sealingPublicB64() const;
    const std::string& displayName() const;
    void setDisplayName(const std::string& name);

    const Bytes& avatar() const;
    const std::string& avatarMime() const;
    void setAvatar(const Bytes& data, const std::string& mime);

    std::string contactDisplayName(const std::string& peerFingerprint) const;
    Bytes contactAvatar(const std::string& peerFingerprint) const;
    bool contactIsPending(const std::string& peerFingerprint) const;
    bool contactAcceptInFlight(const std::string& peerFingerprint) const;
    void renameContact(const std::string& peerFingerprint, const std::string& name);

    void syncChatPinToSelf(const std::string& peerFingerprint, bool pinned);
    void syncReadToSelf(const std::string& peerFingerprint, std::int64_t sentAtMs);
    void syncChatClearToSelf(const std::string& peerFingerprint);
    void syncAccountPrefsToSelf();

    void removeContact(const std::string& peerFingerprint);
    void removeContactEverywhere(const std::string& peerFingerprint);

    bool isSavedChat(const std::string& peerFingerprint) const;
    void clearSaved();

    bool isBlocked(const std::string& peerFingerprint) const;
    std::vector<std::string> blockedPeers() const;
    void setBlocked(const std::string& peerFingerprint, bool blocked);

    bool contactNotifications(const std::string& peerFingerprint) const;
    bool contactCalls(const std::string& peerFingerprint) const;
    void setContactNotifications(const std::string& peerFingerprint, bool on);
    void setContactCalls(const std::string& peerFingerprint, bool allowed);

    bool acceptCalls() const { return acceptCalls_; }
    void setAcceptCalls(bool accept);

    bool sendReceipts() const { return sendReceipts_; }
    void setSendReceipts(bool on);

    void registerAccount();

    void registerSelfHosted();

    void publishRouting();

    bool sendVoice(const std::string& peerFingerprint, const Bytes& opus, std::int64_t durationMs,
        const std::string& e2eId = {},
        const DeliveryWatch& watch = {},
        const std::string& replyTo = {}, bool forwarded = false);

    void putPicture(const std::string& e2eId, const Bytes& bytes);
    std::optional<Bytes> picture(const std::string& e2eId) const;
    bool hasPicture(const std::string& e2eId) const;
    void putVoice(const std::string& e2eId, const Bytes& bytes);
    std::optional<Bytes> voice(const std::string& e2eId) const;

    std::vector<Client::DeviceEntry> devices();
    void retireDevice(const std::string& clientId);
    void retireThisDevice();
    void closeAccountOnServer();

    PortalInfo serverPortalInfo();

    std::string ensureI2pDestination();
    std::string loadI2pDestination(const Bytes& privateKeysDat);
    bool hasI2pDestination() const;
    // The stable base32 address (without the ".b32.i2p" suffix), or empty.
    std::string i2pAddress() const;
    void deleteI2pDestination();

    void disableI2pDest();
    I2pDestStatus i2pDestStatus();

    struct ApprovalState {
        bool pending = false;
        std::string message;
    };
    ApprovalState approvalState() const { return approval_; }
    StorageUsage storageUsage();
    std::int64_t delegationDays() const;
    void setDelegationDays(std::int64_t days, bool announce = true);

    bool refreshI2pTransientIfDue(std::int64_t now, std::int64_t leadSeconds);
    std::int64_t renewI2pTransient(int days);
    Bytes i2pTransient() const;
    // The active transient as base64 (the form the server feeds its I2P router).
    std::string i2pTransientBase64() const;

    using AddressDecisionFn
        = std::function<void(const std::string& servedHost, const std::string& ourHost)>;
    void onAddressDecision(AddressDecisionFn handler) { addressDecision_ = std::move(handler); }

    void publishThisDeviceAddress();
    void publishFreshAddress();

    std::string signLogin(const std::string& challenge) const;

    std::shared_ptr<LoginSigner> loginSigner() const;

    void askDevicesForContacts();

    std::vector<WireEvent> connectionLog() const;
    void clearConnectionLog();

    std::string inviteUri() const;
    std::string contactInviteUri(const std::string& peerFingerprint) const;
    bool hasOwnRouting() const;
    DestinationInfo serverDestination();
    void refreshOwnCard();
    std::string destinationOwner() const;

    void acceptContactRequest(const std::string& peerFingerprint);

    std::string addByInvite(const std::string& inviteUri, const std::string& text);

    std::string addByAlias(const std::string& alias, const std::string& text);

    struct ContactFetchContext {
        std::string identityPem;        // unencrypted in-memory private PEM
        std::string clientId;
        ServerEndpoint endpoint;
        std::filesystem::path i2pDataDir;
        ResolverCoordinate resolver;
        bool i2pEnabled = false;
        bazarish::i2p::Privacy blobFetchPrivacy = bazarish::i2p::Privacy::eMax;
        std::string destinationOwner;
        Bytes servingSealingKeyDer;
    };
    struct AliasErrandContext {
        std::string identityPem;        // unencrypted in-memory private PEM
        ResolverCoordinate resolver;
        bool i2pEnabled = false;
        bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
        std::string destinationOwner;
        std::string fingerprint;
        std::string dest;
        std::string view;
        std::string pushedDest;
        std::string pushedView;
        FetchTransport transport;
    };

    struct AliasStatusAnswer {
        AliasStatus status;
        Bytes recordDer;
        Bytes delegationDer;
    };

    struct AliasErrandResult {
        bool ok = false;
        std::string error;
        bool haveStatus = false;
        AliasStatusAnswer answer;
        bool pointed = false;
        std::string pushedDest;
        std::string pushedView;
    };

    struct ContactCardRequest {
        bool byAlias = false;
        std::string uriOrAlias;
        std::string introText;
        std::string requestId;
    };

    struct PendingContactAdd {
        std::string opId;
        ContactCardRequest request;
    };
    std::vector<PendingContactAdd> pendingContactAdds() const;
    void notePendingContactAdd(const PendingContactAdd& pending);
    void forgetPendingContactAdd(const std::string& opId);
    struct ContactCardResolved {
        bool ok = false;
        std::string error;
        std::string fingerprint;
        ContactInfo info;
        std::string displayName;
        std::string introText;
        std::string view;
        std::string requestId;
    };

    ContactFetchContext contactFetchContext() const;
    static std::unique_ptr<Client> makeEventClient(const ContactFetchContext& context);
    static std::vector<PendingEntry> waitForMail(Client& waiter, int waitSeconds);

    static ContactCardResolved resolveContactCard(
        const ContactFetchContext& context, const ContactCardRequest& request);
    std::string commitContactAdd(const ContactCardResolved& resolved);

    void setResolverCoordinate(ResolverCoordinate coordinate);

    bool sendMessage(const std::string& peerFingerprint, const std::string& text,
        const std::string& e2eId = {},
        const DeliveryWatch& watch = {}, const std::string& replyTo = {},
        bool forwarded = false);

    bool sendFile(const std::string& peerFingerprint, const std::filesystem::path& path,
        const std::string& e2eId = {},
        const DeliveryWatch& watch = {}, const std::string& replyTo = {});

    bool sendPicture(const std::string& peerFingerprint, const Bytes& bytes,
        const std::string& name, const std::string& mime, const std::string& e2eId = {},
        const DeliveryWatch& watch = {},
        const std::string& replyTo = {});

    void sendInteractive(const std::string& peerFingerprint, const std::string& text,
        const InlineKeyboard& keyboard, const std::string& e2eId = {},
        const DeliveryWatch& watch = {});

    void sendCommand(const std::string& peerFingerprint, const std::string& command,
        const std::string& args = {}, const std::string& e2eId = {},
        const DeliveryWatch& watch = {});

    void sendCallback(const std::string& peerFingerprint, const std::string& data,
        const std::string& refMessageId = {});

    bool sendEdit(const std::string& peerFingerprint, const std::string& refMessageId,
        const std::string& text, const InlineKeyboard& keyboard = {},
        const DeliveryWatch& watch = {});

    void sendDelete(const std::string& peerFingerprint, const std::string& refMessageId);

    struct AliasHolding {
        std::string alias;
        std::int64_t notAfter = 0;
        bool autoRenew = true;
        bool bindingWanted = false;
        bool bound = false;
    };

    std::vector<AliasHolding> aliasNames() const { return aliasNames_; }

    bool refreshAliasStatus(const FetchTransport& over = {});

    void serviceAliases();

    bool pushAliasDescriptor(const FetchTransport& over = {});

    AliasErrandContext aliasErrandContext() const;
    static AliasErrandResult runAliasErrand(const AliasErrandContext& context);
    void applyAliasErrand(const AliasErrandResult& result);

    bool aliasUpdatePending() const;

    bool aliasServicingDue() const;

    bool aliasDepositCovers() const { return aliasDepositCovers_; }

    struct RoutingPushResult {
        std::size_t told = 0;
        std::size_t failed = 0;
    };

    RoutingPushResult rotateServingKey(
        const std::function<void(const std::string& stage)>& onStage);

    bool contactSharingRefused(const std::string& peerFingerprint) const
    {
        const auto found = contacts_.find(peerFingerprint);
        return found != contacts_.end() && found->second.sharingRefused;
    }

    RoutingPushResult pushRoutingToContacts();

    bool sharingAllowed() const { return sharingAllowed_; }
    void setSharingAllowed(bool allowed);

private:
    std::string sharedView() const { return sharingAllowed_ ? view_ : std::string(); }

public:

    void sendReceipt(const std::string& peerFingerprint, const std::string& refMessageId);

    void sendReaction(const std::string& peerFingerprint, const std::string& refMessageId,
        const std::string& emoji);

    void sendChatClear(const std::string& peerFingerprint);

    bool canWriteTo(const std::string& peerFingerprint) const;

    std::string deliveryIdFor(const std::string& e2eId, const std::string& mailbox) const;

    void requestFile(const std::string& peerFingerprint, const std::string& e2eId,
        const std::filesystem::path& dest);

    void cancelTransfer(const std::string& e2eId);

    void setTransferHandler(TransferEventFn handler);

    void forgetSentFilesFor(const std::string& peerFingerprint);
    void unsend(const std::string& e2eId);

    void setTransferPrivacy(bazarish::i2p::Privacy privacy);

    void releaseI2pLinks();

    enum class CallState {
        eIdle,
        eOutgoing,
        eIncoming,
        eActive,
    };

    enum class CallOutcome {
        eAnswered,
        eNoAnswer,
        eDeclined,
        eMissed,
        eCancelled,
        eBusy,
        eRefused,
    eRefusedHere,
    };

    struct CompletedCall {
        std::string peer;
        bool incoming = false;
        CallOutcome outcome = CallOutcome::eMissed;
        std::int64_t durationSec = 0;
    };

    struct CallInfo {
        CallState state = CallState::eIdle;
        std::string callId;
        std::string peerFingerprint;
        bool muted = false;
        std::uint64_t packetsSent = 0;
        std::uint64_t packetsReceived = 0;
        std::string stage;
        bool peerRinging = false;
        std::int64_t connectedAtMs = 0;
        float inputLevel = 0.0F;
        float outputLevel = 0.0F;
    };

    using AudioSourceFactory = std::function<std::unique_ptr<AudioSource>()>;
    using AudioSinkFactory = std::function<std::unique_ptr<AudioSink>()>;
    void setFetchTransport(FetchTransport transport);
    void setOutboundCourier(std::unique_ptr<OutboundCourier> courier);

    void setAudioBackend(AudioSourceFactory sourceFactory, AudioSinkFactory sinkFactory);

    void startAudioCall(const std::string& peerFingerprint);

    void acceptCall(const std::string& callId);

    void declineCall(const std::string& callId);

    void endCall();

    void setCallMuted(bool muted);

    CallInfo currentCall() const;

    std::vector<CompletedCall> takeCallLog();
    void tickCalls();

    std::vector<IncomingMessage> sync(bool autoAckSurfaced = true, std::size_t maxItems = 0);
    static constexpr std::size_t kPendingItemsPerPass = 5;
    void setSwitchedOff(bool off) { switchedOff_ = off; }
    bool switchedOff() const { return switchedOff_; }
    void requireSwitchedOn() const;
    bool morePending() const { return morePending_; }
    void flushPendingEchoes();
    std::size_t awaitingAcks() const { return awaitingAck_.size(); }

    void ackPending(const std::string& pendingId);
    void forgetPending(const std::string& pendingId);
    void releasePending(const std::string& pendingId);

    void onServerAnswered(std::function<void()> tell);

    using AckSink = std::function<void(const std::string& pendingId)>;
    void setAckSink(AckSink sink);

    using SelfSendSink
        = std::function<void(std::string deliveryId, Bytes sealed, std::string kind)>;
    void setSelfSendSink(SelfSendSink sink);
    void submitPrepared(
        const std::string& deliveryId, const Bytes& sealed, const std::string& kind);

    struct MailboxItem {
        std::string pendingId;
        Bytes blob;
    };
    static std::vector<MailboxItem> fetchMailbox(
        Client& client, const std::vector<PendingEntry>& waiting, std::size_t maxItems);
    void holdFetched(std::vector<MailboxItem> items);

    bool hasContact(const std::string& peerFingerprint) const;
    std::vector<std::string> contactFingerprints() const;

    ~Session();
    Session(Session&&) noexcept;
    Session& operator=(Session&&) noexcept;

private:
    Session(std::filesystem::path accountFile, std::unique_ptr<Client> client, Key sealingKey,
        std::map<std::string, Contact> contacts);

    void storeCard(const PublishResult& result);
    std::int64_t currentCardIssuedAt() const;
    std::string ownRoutingHost() const;

    void sendSelf(nlohmann::json inner);
    bool saveToSelf(nlohmann::json message);
    void persistBlocked();
    void persistPendingRevokes();
    void retryPendingRevokes();
    Bytes passIdFor(const std::string& peerFingerprint) const;
    std::string registerPassFor(const std::string& peerFingerprint);
    void revokePassFor(const std::string& peerFingerprint);

    void noteChosenName(const std::string& peerFingerprint, const std::string& name);
    std::string chosenName(const std::string& peerFingerprint) const;
    void forgetChosenName(const std::string& peerFingerprint);

    void requestWithInfo(const std::string& requestId, const std::string& peerFingerprint,
        const std::string& text,
        const ContactInfo& info, const std::string& displayName = {},
        const std::string& descriptorView = {});

    FetchTransport fetchTransport() const;

    nlohmann::json contactBookEntry(
        const std::string& peerFingerprint, const Contact& contact) const;
    void sendContactBookTo(const std::string& toDevice);
    void applyContactBook(const nlohmann::json& entries);

    IdentityKeys knownKeysFor(const std::string& peerFingerprint) const;
    static void rememberKeys(Contact& contact, const IdentityKeys& keys);

    void submitSignedToSelf(
        nlohmann::json inner, const std::string& kind, bool later = false) const;

    void noteWire(bool outgoing, std::string what, std::string status, std::string detail) const;
    std::string wireName(const std::string& peerFingerprint) const;

    nlohmann::json envelope(const std::string& type, const std::string& id,
        nlohmann::json payload = nlohmann::json::object()) const;

    bool sendContent(const std::string& peerFingerprint, nlohmann::json inner,
        const DeliveryWatch& watch = {}, bool waitForOutcome = false,
        bool establishOnFirstReply = true);

    void syncI2pMasterToSelf();
    bool adoptI2pMasterFromOwnMailbox(const std::string& wantedHost = {});
    bool reconcileI2pAddress();
    void askDevicesForI2pMaster(const std::string& servedHost);
    void replaceI2pMaster(const Bytes& privateKeysDat);

    void syncDelegationTermToSelf();

    void echoSentToSelf(const std::string& peerFingerprint, const nlohmann::json& inner);

    void maybeSendAvatarToContact(const std::string& peerFingerprint, bool removal = false);
    void syncAvatarToSelf();
    void syncContactNameToSelf(const std::string& peerFingerprint, const std::string& name);
    void storeOwnAvatar(const Bytes& data, const std::string& mime);
    void storeContactAvatar(
        const std::string& peerFingerprint, const Bytes& data, const std::string& mime);
    void persistSealedBlob(const std::string& filename, const Bytes& blob) const;

    std::shared_ptr<bazarish::i2p::Endpoint> openCallMediaSession();
    void startCall(const std::string& peerFingerprint);
    void startCallMedia();
    void clearCall();
    void announceCallTaken(const std::string& callId);
    bool sendCallSignal(
        const std::string& peerFingerprint, const std::string& type, nlohmann::json extra);
    void handleCallSignal(const std::string& type, const std::string& from,
        const nlohmann::json& body, IncomingMessage& message);
    void logCompletedCall(CallOutcome outcome);

    bool deliver(const std::string& toDest, const Key& servingSealingKey,
        const std::string& deliveryClass, const std::string& mailbox,
        const Bytes& pass, const Bytes& payload,
        const DeliveryWatch& watch = {}, bool waitForOutcome = true,
        const std::string& e2eId = {});
    OutboundCourier& outboundCourier();
    void persistContacts() const;
    void persistMeta() const;
    nlohmann::json contactsToJson() const;

    std::filesystem::path accountPath_;
    std::unique_ptr<AccountDb> db_;
    struct Outbound {
        std::mutex mutex;
        std::unique_ptr<OutboundLeases> leases;
        std::unique_ptr<OutboundCourier> courier;
    };
    std::shared_ptr<Outbound> outbound_ = std::make_shared<Outbound>();
    bool announceTransfer(const std::string& type, const std::string& peerFingerprint,
        const std::filesystem::path& path, const std::string& e2eId, const DeliveryWatch& watch,
        const std::string& replyTo);

    void serveRequestedFile(const std::string& peerFingerprint, const std::string& fileId,
        const std::string& forAsk);
    void dropServe(const std::string& serveId, const std::shared_ptr<std::atomic<bool>>& cancel);
    struct StoppedHalf {
        std::string peer;
        std::string ask;
    };
    bool awaitingAsk(const std::string& ask) const;
    std::vector<StoppedHalf> stopTransfer(const std::string& fileId,
        const std::string& fromPeer = {}, const std::string& forAsk = {});
    void startAnnouncedFetch(const FileOffer& offer, const std::string& peer);
    void emitTransfer(const std::string& e2eId, TransferState state, std::uint64_t bytes,
        std::uint64_t total, const std::string& error = {},
        const std::string& stage = {},
        const std::string& peer = {});
    void loadSentFiles();
    void persistSentFiles() const;

    std::unique_ptr<Client> client_;
    ResolverCoordinate resolverCoordinate_ = defaultResolverCoordinate();

    std::vector<AliasHolding> aliasNames_;
    std::int64_t aliasCheckAfter_ = 0;
    std::int64_t aliasStatusAt_ = 0;
    bool aliasDepositCovers_ = true;
    std::string aliasPushedDest_;
    std::string aliasPushedView_;

    nlohmann::json aliasNamesToJson() const;
    void adoptAliasStatus(const AliasStatus& status);
    void noteAliasesBound();
    FetchTransport heldTransport() const;
    void relayAliasStatus(const Bytes& statusDer, const Bytes& delegationDer);
    void scheduleNextAliasCheck(std::int64_t from);
    void serviceAliasesAfterMove();
    bool switchedOff_ = false;
    bazarish::i2p::Privacy transferPrivacy() const;
    std::optional<bazarish::i2p::Privacy> transferPrivacy_;
    bazarish::i2p::Router& i2pRouter() const;

    AudioSourceFactory audioSourceFactory_;
    AudioSinkFactory audioSinkFactory_;

    struct ActiveCall {
        CallState state = CallState::eIdle;
        std::string callId;
        std::string peerFingerprint;
        std::string peerMediaDest;
        Bytes mediaKey;
        bool initiator = false;
        bool muted = false;
        std::int64_t startedAtMs = 0;
        std::int64_t invitedAtMs = 0;
        std::int64_t deliveredAtMs = 0;
        std::string stage;
        std::int64_t peerRingingAtMs = 0;
        std::int64_t connectedAtMs = 0;
        std::uint64_t lastPacketsReceived = 0;
        std::int64_t lastPacketAtMs = 0;
        std::shared_ptr<bazarish::i2p::Endpoint> dgram;
        std::unique_ptr<I2pCallTransport> transport;
        std::unique_ptr<CallMedia> media;
    };
    ActiveCall call_;
    std::vector<CompletedCall> pendingCallLog_;
    std::map<std::string, SentFile> sentFiles_;
    struct PendingTransfer {
        std::filesystem::path dest;
        std::shared_ptr<std::atomic<bool>> cancel;
        std::string peer;
        std::string ask;
        bool fetching = false;
    };
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
    struct PairingRegistry {
        std::mutex mutex;
        std::shared_ptr<std::atomic<bool>> cancel;
        std::weak_ptr<bazarish::i2p::Endpoint> endpoint;
        PairingEventFn onEvent;
    };
    std::shared_ptr<PairingRegistry> pairing_ = std::make_shared<PairingRegistry>();
    Key sealingKey_;
    std::string deliveryIdSeed_;
    bool morePending_ = false;
    std::deque<std::string> endedCalls_;
    std::set<std::string> awaitingAck_;
    std::function<void()> serverAnswered_;
    AckSink ackSink_;
    SelfSendSink selfSendSink_;
    std::map<std::string, Bytes> fetched_;
    void releaseItem(const std::string& pendingId);
    Bytes deliverySecret_;
    std::map<std::string, Contact> contacts_;
    std::set<std::string> blocked_;
    // Pass handles (base64) our server has not confirmed dropping.
    std::set<std::string> pendingPassRevokes_;
    std::vector<std::string> contactsAskedBy_;
    std::string myDest_;
    std::string myServingKeyB64_;
    std::string view_;
    std::int64_t delegationDays_ = kDefaultDelegationDays;
    FetchTransport fetchTransportOverride_;
    std::string name_;
    Bytes avatar_;
    std::string avatarMime_;
    std::string cardB64_;
    ApprovalState approval_;
    bool encrypted_ = false;
    bool sharingAllowed_ = true;
    bool acceptCalls_ = true;
    bool sendReceipts_ = true;
    std::string passphrase_;
    struct EchoQueue {
        std::mutex mutex;
        std::vector<std::pair<std::string, nlohmann::json>> pending;
        std::vector<std::string> established;
        std::vector<std::string> notEstablished;
    };
    std::shared_ptr<EchoQueue> echoQueue_ = std::make_shared<EchoQueue>();
    AddressDecisionFn addressDecision_;
    Bytes i2pMaster_;
    std::string i2pAddress_;
    Bytes i2pTransient_;

    void persistI2pBlob(const std::string& filename, const Bytes& blob) const;
};

}  // namespace bazarish::client
