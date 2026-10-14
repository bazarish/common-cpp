// Bazarish project (c) 2026
#include "OutboundLeases.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Log.hpp>

#include <chrono>
#include <utility>

namespace bazarish::client {

constexpr std::chrono::milliseconds kSlowPrepare{300};

namespace {

constexpr std::chrono::seconds kSweepInterval{30};
constexpr char kLeaseLabel[] = "Outbound delivery";
constexpr char kLeaseLabelPrefix[] = "Outbound for ";
constexpr char kSharedLeaseLabel[] = "Outbound for everyone";
constexpr char kSharedLeaseKey[] = "";

class I2pDeliveryStream final : public DeliveryStream {
public:
    I2pDeliveryStream(std::shared_ptr<bazarish::i2p::Endpoint> endpoint,
        std::unique_ptr<bazarish::i2p::Stream> stream)
        : endpoint_(std::move(endpoint))
        , stream_(std::move(stream))
    {
    }

    void readExact(void* const buffer, const std::size_t size) override
    {
        stream_->readExact(buffer, size);
    }

    void writeAll(const void* const data, const std::size_t size) override
    {
        stream_->writeAll(data, size);
    }

    void close() override { stream_->close(); }

private:
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint_;
    const std::unique_ptr<bazarish::i2p::Stream> stream_;
};

}  // namespace

bool leaseSpent(const std::chrono::steady_clock::time_point created,
    const std::chrono::steady_clock::time_point lastUsed,
    const std::chrono::steady_clock::time_point now)
{
    return now - created >= kLeaseMaxLife || now - lastUsed >= kLeaseIdleLife;
}

std::string leaseKeyFor(
    const OutboundAddressing addressing, const bool ownAddress, const std::string& toDest)
{
    return addressing == OutboundAddressing::eOneForAll && !ownAddress
        ? std::string(kSharedLeaseKey)
        : toDest;
}

OutboundLeases::OutboundLeases(bazarish::i2p::Router& router, std::string owner)
    : router_(router)
    , owner_(std::move(owner))
{
    sweeper_ = std::thread(&OutboundLeases::sweeperLoop, this);
}

std::string OutboundLeases::labelFor(const std::string& peerName)
{
    return peerName.empty() ? std::string(kLeaseLabel) : kLeaseLabelPrefix + peerName;
}

OutboundLeases::~OutboundLeases()
{
    running_ = false;
    cv_.notify_all();
    if (sweeper_.joinable()) {
        sweeper_.join();
    }
}

void OutboundLeases::dropExpired(const std::chrono::steady_clock::time_point now)
{
    const bazarish::i2p::Privacy privacy = tunnelPrivacy();
    for (auto it = leases_.begin(); it != leases_.end();) {
        if (leaseSpent(it->second.created, it->second.lastUsed, now)
            || it->second.privacy != privacy || it->second.endpoint->lost()) {
            it = leases_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string OutboundLeases::keyForLocked(const std::string& toDest) const
{
    return leaseKeyFor(addressing_, own_.count(toDest) != 0, toDest);
}

std::shared_ptr<bazarish::i2p::Endpoint> OutboundLeases::held(const std::string& toDest)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return heldLocked(keyForLocked(toDest));
}

std::shared_ptr<bazarish::i2p::Endpoint> OutboundLeases::heldLocked(const std::string& key)
{
    const auto now = std::chrono::steady_clock::now();
    dropExpired(now);
    const auto found = leases_.find(key);
    if (found == leases_.end()) {
        return nullptr;
    }
    found->second.lastUsed = now;
    return found->second.endpoint;
}

bool OutboundLeases::prepare(const std::string& toDest, const std::string& peerName)
{
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
    bool making = false;
    std::string key;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        key = keyForLocked(toDest);
        prepared_.wait(lock, [this, &key]() { return preparing_.count(key) == 0; });
        endpoint = heldLocked(key);
        if (!endpoint) {
            preparing_.insert(key);
            making = true;
        }
    }
    const std::string label = key == toDest ? labelFor(peerName) : std::string(kSharedLeaseLabel);
    if (making) {
        const log::Slow timed("making an address ready to send from", kSlowPrepare);
        try {
            endpoint = acquireWarmDest();
            if (endpoint) {
                router_.retagEndpoint(*endpoint, label, owner_);
            } else {
                log::info("no warm address for {}: building one, which is tunnels",
                    log::redact(toDest));
                bazarish::i2p::EndpointConfig config;
                config.privacy = tunnelPrivacy();
                config.published = false;
                config.label = label;
                config.owner = owner_;
                endpoint = router_.createEndpoint(config);
            }
        } catch (...) {
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                preparing_.erase(key);
            }
            prepared_.notify_all();
            throw;
        }
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            const auto now = std::chrono::steady_clock::now();
            const auto found = leases_.find(key);
            if (found != leases_.end()
                && !leaseSpent(found->second.created, found->second.lastUsed, now)) {
                endpoint = found->second.endpoint;
            } else {
                leases_[key] = Lease{endpoint, now, now, tunnelPrivacy()};
            }
            preparing_.erase(key);
        }
        prepared_.notify_all();
    }
    const bool ready = endpoint->waitReady(std::chrono::seconds(kOutboundDestReadySeconds));
    if (!ready) {
        log::warn("the address for {} has no tunnels after {} s", log::redact(toDest),
            kOutboundDestReadySeconds);
    }
    return ready;
}

std::shared_ptr<DeliveryStream> OutboundLeases::openStream(
    const std::string& toDest, const std::chrono::seconds timeout)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint = held(toDest);
    if (!endpoint) {
        return nullptr;
    }
    std::unique_ptr<bazarish::i2p::Stream> stream = endpoint->connect(toDest, timeout);
    if (!stream) {
        return nullptr;
    }
    return std::make_shared<I2pDeliveryStream>(endpoint, std::move(stream));
}

void OutboundLeases::release(const std::string& toDest)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    leases_.erase(toDest);
    own_.erase(toDest);
}

void OutboundLeases::retire(const std::string& toDest)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    leases_.erase(keyForLocked(toDest));
}

void OutboundLeases::clear()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    leases_.clear();
}

void OutboundLeases::setAddressing(const OutboundAddressing addressing)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (addressing_ == addressing) {
        return;
    }
    addressing_ = addressing;
    leases_.clear();
}

void OutboundLeases::keepOwn(const std::string& toDest)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    own_.insert(toDest);
}

void OutboundLeases::sweeperLoop()
{
    while (running_) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (cv_.wait_for(lock, kSweepInterval, [this]() { return !running_.load(); })) {
            return;
        }
        try {
            dropExpired(std::chrono::steady_clock::now());
        } catch (const std::exception& error) {
            bazarish::log::warn("outbound leases: sweep failed: {}", error.what());
        }
    }
}

}  // namespace bazarish::client
