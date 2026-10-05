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

inline constexpr int kLeaseTermSeconds = 600;
inline constexpr int kOutboundDestReadySeconds = 180;

class OutboundLeases {
public:
    OutboundLeases(bazarish::i2p::Router& router, std::string owner);
    ~OutboundLeases();

    bool prepare(const std::string& toDest, const std::string& peerName);
    std::shared_ptr<DeliveryStream> openStream(
        const std::string& toDest, std::chrono::seconds timeout);
    void clear();

private:
    static std::string labelFor(const std::string& peerName);

    void sweeperLoop();
    void dropExpired(std::chrono::steady_clock::time_point now);
    std::shared_ptr<bazarish::i2p::Endpoint> held(const std::string& toDest);
    std::shared_ptr<bazarish::i2p::Endpoint> heldLocked(const std::string& toDest);

    struct Lease {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        std::chrono::steady_clock::time_point expiresAt;
        bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
    };

    bazarish::i2p::Router& router_;
    const std::string owner_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::map<std::string, Lease> leases_;
    std::set<std::string> preparing_;
    std::condition_variable prepared_;
    std::atomic<bool> running_{true};
    std::thread sweeper_;
};

}  // namespace bazarish::client
