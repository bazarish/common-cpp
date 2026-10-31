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
#include <set>
#include <string>
#include <thread>

namespace bazarish::client {

inline constexpr std::chrono::seconds kLeaseMaxLife{3600};
inline constexpr std::chrono::seconds kLeaseIdleLife{600};
inline constexpr int kOutboundDestReadySeconds = 180;

bool leaseSpent(std::chrono::steady_clock::time_point created,
    std::chrono::steady_clock::time_point lastUsed, std::chrono::steady_clock::time_point now);

enum class OutboundAddressing { eOnePerCorrespondent, eOneForAll };

std::string leaseKeyFor(OutboundAddressing addressing, bool ownAddress, const std::string& toDest);

class OutboundLeases {
public:
    OutboundLeases(bazarish::i2p::Router& router, std::string owner);
    ~OutboundLeases();

    bool prepare(const std::string& toDest, const std::string& peerName);
    std::shared_ptr<DeliveryStream> openStream(
        const std::string& toDest, std::chrono::seconds timeout);
    void release(const std::string& toDest);
    void retire(const std::string& toDest);

    void setAddressing(OutboundAddressing addressing);
    void keepOwn(const std::string& toDest);

private:
    static std::string labelFor(const std::string& peerName);

    void sweeperLoop();
    void dropExpired(std::chrono::steady_clock::time_point now);
    std::shared_ptr<bazarish::i2p::Endpoint> held(const std::string& toDest);
    std::shared_ptr<bazarish::i2p::Endpoint> heldLocked(const std::string& key);
    std::string keyForLocked(const std::string& toDest) const;

    struct Lease {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        std::chrono::steady_clock::time_point created;
        std::chrono::steady_clock::time_point lastUsed;
        bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
    };

    bazarish::i2p::Router& router_;
    const std::string owner_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::map<std::string, Lease> leases_;
    std::set<std::string> preparing_;
    OutboundAddressing addressing_ = OutboundAddressing::eOnePerCorrespondent;
    std::set<std::string> own_;
    std::condition_variable prepared_;
    std::atomic<bool> running_{true};
    std::thread sweeper_;
};

}  // namespace bazarish::client
