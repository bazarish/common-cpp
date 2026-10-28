// Bazarish project (c) 2026
#pragma once

#include "Authorship.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::client {

inline constexpr std::size_t kMaxPresenceReaders = i2p::kMaxLeaseSetReaders;
inline constexpr std::size_t kPresenceSubscriptionIdBytes = 8;

struct PresenceLinkConfig {
    std::optional<i2p::Keys> keys;
    std::vector<Bytes> readers;
    Bytes readerKey;
};

class PresenceLink {
public:
    virtual ~PresenceLink() = default;
    virtual std::string host() const = 0;
    virtual void send(const std::string& host, const Bytes& datagram) = 0;
    virtual std::optional<Bytes> receive(std::chrono::milliseconds wait) = 0;
    // The transport took the address down (a gateway's lapsed delegation); it is raised again.
    virtual bool lost() const = 0;
    virtual bool ready() const = 0;
};

using PresenceNet = std::function<std::unique_ptr<PresenceLink>(const PresenceLinkConfig&)>;

struct PresenceWatch {
    Bytes id;
    Bytes key;
    std::string from;
    std::string reply;
    std::int64_t sentAt = 0;
};

// Sealed by the hybrid seal to the watched account; signed by the Ed25519 half of the identity alone.
Bytes presenceWatchFrame(const PresenceWatch& watch, const Key& signer, const Key& recipientSealing);

bazarish::i2p::EndpointConfig presenceEndpointShape();
PresenceNet i2pPresenceNet(std::filesystem::path routerDir, std::string owner);

struct PresenceContact {
    std::string fingerprint;
    Bytes sealingKeyDer;
    IdentityKeys identity;
    Bytes presenceKeyDer;
    std::string presenceDest;
};

struct PresenceAccount {
    std::string fingerprint;
    std::string identityPem;
    std::string sealingPem;
    Bytes readerKey;
    Bytes destKeys;
};

struct PresenceState {
    bool online = false;
    bool typing = false;

    bool operator==(const PresenceState&) const = default;
};

using PresenceSink = std::function<void(const std::string& peer, const PresenceState& state)>;

struct PresenceTimings {
    std::chrono::milliseconds watchRetry{5000};
    std::chrono::milliseconds renewEvery{15000};
    std::chrono::milliseconds subscriptionLife{30000};
    std::chrono::milliseconds onlineTail{60000};
    std::chrono::milliseconds typingPulse{5000};
    std::chrono::milliseconds readersSettle{10000};
    // How long a gone holder's lease set can still be found: i2pd's TUNNEL_EXPIRATION_TIMEOUT.
    std::chrono::milliseconds leaseSetLife{660000};
    std::chrono::milliseconds tick{250};
};

class Presence {
public:
    Presence(PresenceAccount account, PresenceNet net, PresenceSink sink,
        PresenceTimings timings = {});
    ~Presence();
    Presence(const Presence&) = delete;
    Presence& operator=(const Presence&) = delete;

    void setFocused(bool focused);
    void setShown(bool shown);
    // In chat-list order: the first kMaxPresenceReaders may read this account's presence.
    void setContacts(std::vector<PresenceContact> ordered);
    // The contacts on screen: the open conversation and the visible rows of the chat list.
    void watch(std::vector<std::string> peers);
    void typed(const std::string& peer);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::client
