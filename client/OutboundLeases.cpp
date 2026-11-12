// Bazarish project (c) 2026
#include "OutboundLeases.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Log.hpp>

#include <chrono>
#include <stdexcept>
#include <utility>

namespace bazarish::client {

constexpr std::chrono::milliseconds kSlowPrepare{300};

namespace {

constexpr std::chrono::seconds kSweepInterval{30};
constexpr char kLeaseLabel[] = "Outbound delivery";
constexpr char kLeaseLabelPrefix[] = "Outbound for ";
constexpr char kSharedLeaseLabel[] = "Outbound for everyone";
constexpr char kSharedLeaseKey[] = "";
const std::string kOwnLeasePrefix = "own:";

class I2pDeliveryStream final : public DeliveryStream {
public:
    I2pDeliveryStream(std::shared_ptr<bazarish::i2p::Endpoint> endpoint,
        std::unique_ptr<bazarish::i2p::Stream> stream)
        : endpoint_(std::move(endpoint))
        , stream_(std::move(stream))
    {
    }

    std::size_t readSome(const ByteBuffer buffer) override { return stream_->readSome(buffer); }

    void writeAll(const ByteView data) override { stream_->writeAll(data); }

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
    if (ownAddress) {
        return kOwnLeasePrefix + toDest;
    }
    return addressing == OutboundAddressing::eOneForAll ? std::string(kSharedLeaseKey) : toDest;
}

OutboundLeases::OutboundLeases(bazarish::i2p::Router& router, std::string accountLabel)
    : router_(router)
    , accountLabel_(std::move(accountLabel))
{
    sweeper_ = std::jthread([this](const std::stop_token& stop) { sweeperLoop(stop); });
}

std::string OutboundLeases::labelFor(const std::string& peerName)
{
    return peerName.empty() ? std::string(kLeaseLabel) : kLeaseLabelPrefix + peerName;
}

void OutboundLeases::stop()
{
    std::vector<std::shared_ptr<bazarish::i2p::Endpoint>> standing;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        for (const auto& [key, lease] : leases_) {
            standing.push_back(lease.endpoint);
        }
        leases_.clear();
    }
    prepared_.notify_all();
    for (const std::shared_ptr<bazarish::i2p::Endpoint>& endpoint : standing) {
        endpoint->stop();
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
        prepared_.wait(lock, [this, &key]() { return preparing_.count(key) == 0 || stopped_; });
        if (stopped_) {
            return false;
        }
        endpoint = heldLocked(key);
        if (!endpoint) {
            preparing_.insert(key);
            making = true;
        }
    }
    const bool shared = key == kSharedLeaseKey;
    const std::string label = shared ? std::string(kSharedLeaseLabel) : labelFor(peerName);
    if (making) {
        const log::Slow timed("making an address ready to send from", kSlowPrepare);
        const bazarish::i2p::Privacy privacy = tunnelPrivacy();
        try {
            endpoint = acquireWarmDest(privacy);
            if (endpoint) {
                router_.retagEndpoint(*endpoint, label, accountLabel_);
            } else {
                log::info("no warm address for {}: building one, which is tunnels",
                    log::redact(toDest));
                bazarish::i2p::EndpointConfig config;
                config.privacy = privacy;
                config.published = false;
                config.label = label;
                config.accountLabel = accountLabel_;
                if (!shared) {
                    config.target = toDest;
                }
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
        bool late = false;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            late = stopped_;
            if (!late) {
                const auto now = std::chrono::steady_clock::now();
                const auto found = leases_.find(key);
                if (found != leases_.end()
                    && !leaseSpent(found->second.created, found->second.lastUsed, now)) {
                    endpoint = found->second.endpoint;
                } else {
                    leases_[key] = Lease{endpoint, now, now, privacy};
                }
            }
            preparing_.erase(key);
        }
        prepared_.notify_all();
        if (late) {
            endpoint->stop();
            return false;
        }
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
    leases_.erase(kOwnLeasePrefix + toDest);
    own_.erase(toDest);
}

std::optional<bazarish::i2p::LeaseSetRefresh> OutboundLeases::lookup(const std::string& toDest)
{
    if (!router_.capabilities().leaseSetRefresh) {
        return std::nullopt;
    }
    if (!prepare(toDest, {})) {
        throw std::runtime_error("no address with tunnels to look the recipient up from");
    }
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint = held(toDest);
    if (!endpoint) {
        throw std::runtime_error("the address to look the recipient up from went away");
    }
    return router_.refreshLeaseSet(endpoint->routingHost(), toDest);
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
    leases_.erase(kOwnLeasePrefix + toDest);
}

void OutboundLeases::sweeperLoop(const std::stop_token& stop)
{
    std::unique_lock<std::mutex> lock(mutex_);
    const auto stopping = [&stop]() { return stop.stop_requested(); };
    while (!sweep_.wait_for(lock, stop, kSweepInterval, stopping)) {
        try {
            dropExpired(std::chrono::steady_clock::now());
        } catch (const std::exception& error) {
            bazarish::log::warn("outbound leases: sweep failed: {}", error.what());
        }
    }
}

}  // namespace bazarish::client
