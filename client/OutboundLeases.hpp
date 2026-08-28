// Bazarish project (c) 2026
#pragma once

#include "OutboundCourier.hpp"

#include <bazarish/I2p.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace bazarish::client {

// How long one destination carries this account's mail to one correspondent. A
// tunnel's own lifetime: past it the destination would be rebuilding its tunnels
// anyway.
inline constexpr int kLeaseTermSeconds = 600;
// A destination built cold needs its own tunnels before it can dial; one taken
// from the warm pool already has them.
inline constexpr int kOutboundDestReadySeconds = 180;

// Which destination this account's mail to one correspondent leaves from.
//
// Sending from the account's own serving destination would hand the recipient's
// server a stable name for the sender: one address, every message, every
// recipient. Mail leaves from a destination held for one term and then dropped,
// so what the far end can group together is one term of traffic and no more.
//
// One term, one destination, one CORRESPONDENT. A single destination per account
// would let a server that hosts several of our contacts see one address writing
// into several of its mailboxes and read off who we talk to there; the
// per-correspondent key is what keeps each conversation to its own address.
//
// A term rather than a destination per message: inside one term the messages are
// grouped by timing anyway, and a tunnel build per message would buy nothing for
// seconds of latency each time.
class OutboundLeases {
public:
    OutboundLeases(bazarish::i2p::Router& router, std::string owner);
    ~OutboundLeases();

    // Makes ready the address this correspondent's mail leaves from, taking a
    // fresh one when the last term is over. False when this device could not
    // build tunnels for it.
    bool prepare(const std::string& toDest, const std::string& peerName);
    // Dials the correspondent from that address. Null when it cannot be reached
    // inside the timeout.
    std::shared_ptr<DeliveryStream> openStream(
        const std::string& toDest, std::chrono::seconds timeout);
    // Drops every lease at once: the account is closing, or the tunnel profile
    // changed and nothing built under the old one may keep carrying traffic.
    void clear();

private:
    // What this correspondent's address is called in the status view: the name
    // this account knows them by, or nothing when there is none yet - a contact
    // request goes out before the contact exists.
    static std::string labelFor(const std::string& peerName);

    void sweeperLoop();
    // Drops every term that has run out. Called with the lock held.
    void dropExpired(std::chrono::steady_clock::time_point now);
    std::shared_ptr<bazarish::i2p::Endpoint> held(const std::string& toDest);

    struct Lease {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        std::chrono::steady_clock::time_point expiresAt;
        // The hop length it was built at. A user who shortens or lengthens their
        // tunnels means it from the next message, not from the next term.
        bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
    };

    bazarish::i2p::Router& router_;
    const std::string owner_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::map<std::string, Lease> leases_;
    std::atomic<bool> running_{true};
    std::thread sweeper_;
};

}  // namespace bazarish::client
