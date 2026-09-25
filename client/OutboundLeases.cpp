// Bazarish project (c) 2026
#include "OutboundLeases.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Log.hpp>

#include <chrono>
#include <utility>

namespace bazarish::client {

// Making an address ready is instant when there is a warm one and tunnels when
// there is not; past this it is the second kind, and the sender is waiting.
constexpr std::chrono::milliseconds kSlowPrepare{300};

namespace {

// How often expired terms are swept. Well inside a term, so a destination is let
// go close to when it should be rather than at the next message.
constexpr std::chrono::seconds kSweepInterval{30};
// What the router status view calls these destinations.
// What one correspondent's outbound address is called in the status view. The
// name is the local one this account knows them by; before there is a name (a
// contact request precedes the contact) the address stands unnamed.
constexpr char kLeaseLabel[] = "Outbound delivery";
constexpr char kLeaseLabelPrefix[] = "Outbound for ";

// One I2P stream, holding the destination it was opened on: the stream is only
// good for as long as that destination lives.
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
        if (it->second.expiresAt <= now || it->second.privacy != privacy) {
            // Unconditionally: a destination that has carried one correspondent's
            // mail is not handed to another, is not kept because it was busy, and
            // does not outlive the tunnel profile it was built under.
            it = leases_.erase(it);
        } else {
            ++it;
        }
    }
}

std::shared_ptr<bazarish::i2p::Endpoint> OutboundLeases::held(const std::string& toDest)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    dropExpired(std::chrono::steady_clock::now());
    const auto found = leases_.find(toDest);
    return found == leases_.end() ? nullptr : found->second.endpoint;
}

bool OutboundLeases::prepare(const std::string& toDest, const std::string& peerName)
{
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint = held(toDest);
    if (!endpoint) {
        // Everything from here to the tunnels being up is what a person watches
        // as an empty circle: the message has not started travelling yet. It is
        // worth saying which of the two ways it went, because one of them is
        // instant and the other builds tunnels.
        const log::Slow timed("making an address ready to send from", kSlowPrepare);
        // Taken outside the lock: acquiring wakes the pool's warmer, and holding
        // the lock across it would queue every other send behind one refill.
        endpoint = acquireWarmDest();
        if (!endpoint) {
            log::info("no warm address for {}: building one, which is tunnels",
                log::redact(toDest));
        }
        if (endpoint) {
            // A spare belongs to nobody while it waits; from here it carries one
            // correspondent's mail, and the status view should say so.
            router_.retagEndpoint(*endpoint, labelFor(peerName), owner_);
        } else {
            endpoint = router_.createEndpoint(bazarish::i2p::EndpointConfig{
                router_.generateKeys(), tunnelPrivacy(),
                bazarish::i2p::kDefaultTunnelQuantity, false, labelFor(peerName), owner_});
        }
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        const auto found = leases_.find(toDest);
        if (found != leases_.end() && found->second.expiresAt > now) {
            endpoint = found->second.endpoint;  // another send got there first
        } else {
            leases_[toDest]
                = Lease{endpoint, now + std::chrono::seconds(kLeaseTermSeconds), tunnelPrivacy()};
        }
        const bool ready = endpoint->waitReady(std::chrono::seconds(kOutboundDestReadySeconds));
        if (!ready) {
            log::warn("the address for {} has no tunnels after {} s",
                log::redact(toDest), kOutboundDestReadySeconds);
        }
        return ready;
    }
    return endpoint->waitReady(std::chrono::seconds(kOutboundDestReadySeconds));
}

std::shared_ptr<DeliveryStream> OutboundLeases::openStream(
    const std::string& toDest, const std::chrono::seconds timeout)
{
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint = held(toDest);
    if (!endpoint) {
        // The term ran out between preparing an address and dialing from it; the
        // next attempt takes a fresh one.
        return nullptr;
    }
    std::unique_ptr<bazarish::i2p::Stream> stream = endpoint->connect(toDest, timeout);
    if (!stream) {
        return nullptr;
    }
    return std::make_shared<I2pDeliveryStream>(endpoint, std::move(stream));
}

void OutboundLeases::clear()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    leases_.clear();
}

void OutboundLeases::sweeperLoop()
{
    while (running_) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (cv_.wait_for(lock, kSweepInterval, [this]() { return !running_.load(); })) {
            return;
        }
        // Retiring a lease tears a destination down, and the engine under it can
        // fail at that - a router that has gone away, most of all. On this thread
        // that is a sweep that did not happen, said out loud and tried again next
        // time; without the catch it is the whole process going down because a
        // lease could not be closed.
        try {
            dropExpired(std::chrono::steady_clock::now());
        } catch (const std::exception& error) {
            bazarish::log::warn("outbound leases: sweep failed: {}", error.what());
        }
    }
}

}  // namespace bazarish::client
