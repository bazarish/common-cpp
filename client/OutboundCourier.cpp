// Bazarish project (c) 2026
#include "OutboundCourier.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/FederationFrame.hpp>
#include <bazarish/Log.hpp>

#include <algorithm>
#include <exception>

namespace bazarish::client {

namespace {

// Threads draining the queue. Enough that a few unreachable correspondents
// cannot hold up everyone else for the length of their runs, few enough that
// they cost nothing while idle.
constexpr std::size_t kDeliveryWorkers = 4;
// How often the watchdog looks for a reply wait that has run out of time.
constexpr std::chrono::seconds kWatchdogTick{1};

std::string retryPhase(const int attempt, const int attempts)
{
    return std::string(kPhaseRetryPrefix) + std::to_string(attempt) + "/"
        + std::to_string(attempts);
}

// True when the recipient's server signed for this exact delivery. An unsigned
// "delivered" proves nothing: the deliveryId is sealed inside the envelope, so
// only a server that opened it can name it, and the signature is what ties that
// name to the key of the destination that answered.
bool signedForUs(const FederationDeliverResult& reply, const std::string& deliveryId)
{
    if (reply.deliveryId != deliveryId || reply.signature.empty()) {
        return false;
    }
    const Bytes signedBytes(deliveryId.begin(), deliveryId.end());
    try {
        return bazarish::verify(
            Key::fromPublicDer(reply.signerPublicDer), signedBytes, reply.signature);
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

OutboundCourier::OutboundCourier(
    PrepareFn prepare, OpenStreamFn openStream, DeliverySchedule schedule)
    : prepare_(std::move(prepare))
    , openStream_(std::move(openStream))
    , schedule_(std::move(schedule))
{
    watchdog_ = std::thread(&OutboundCourier::watchdogLoop, this);
    for (std::size_t i = 0; i < kDeliveryWorkers; ++i) {
        workers_.emplace_back(&OutboundCourier::workerLoop, this);
    }
}

OutboundCourier::~OutboundCourier()
{
    stop();
}

void OutboundCourier::stop()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        running_ = false;
        // Whatever is still queued is not sent and not remembered: there is no
        // outbound queue on disk, so an unfinished send comes back as failed on
        // the next start and it is the user who decides to send it again.
        queue_.clear();
    }
    cv_.notify_all();
    watchCv_.notify_all();
    for (std::thread& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
    if (watchdog_.joinable()) {
        watchdog_.join();
    }
}

void OutboundCourier::submit(Task task)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        queue_.push_back(std::move(task));
    }
    cv_.notify_one();
}

void OutboundCourier::workerLoop()
{
    while (true) {
        Task task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            std::deque<Task>::iterator pick = queue_.end();
            while (running_) {
                pick = std::find_if(queue_.begin(), queue_.end(), [this](const Task& queued) {
                    return busyDests_.find(queued.toDest) == busyDests_.end();
                });
                if (pick != queue_.end()) {
                    break;
                }
                cv_.wait(lock);
            }
            if (!running_) {
                return;
            }
            task = std::move(*pick);
            queue_.erase(pick);
            busyDests_.insert(task.toDest);
        }
        // Holds the destination for as long as this delivery runs, so the next
        // message to the same correspondent starts after this one finished and
        // the two arrive in the order they were sent.
        struct Release {
            OutboundCourier& courier;
            const std::string& dest;
            ~Release()
            {
                {
                    const std::lock_guard<std::mutex> lock(courier.mutex_);
                    courier.busyDests_.erase(dest);
                }
                courier.cv_.notify_all();
            }
        } release{*this, task.toDest};

        const Outcome outcome = deliverNow(task);
        if (task.onOutcome) {
            task.onOutcome(outcome);
        }
    }
}

OutboundCourier::Outcome OutboundCourier::deliverNow(const Task& task)
{
    if (task.onPhase) {
        task.onPhase(kPhasePreparing);
    }
    if (!prepare_(task.toDest, task.peerName)) {
        Outcome local;
        local.errorMessage = "this device has no I2P address to send from yet";
        return local;
    }
    // The budget starts once there is an address to send from: what it measures
    // is the recipient's reachability, not this router's cold start.
    const std::chrono::steady_clock::time_point deadline
        = std::chrono::steady_clock::now() + schedule_.run;
    Outcome outcome;
    for (int number = 1; number <= schedule_.attempts; ++number) {
        if (number > 1) {
            if (task.onPhase) {
                task.onPhase(retryPhase(number, schedule_.attempts));
            }
            std::unique_lock<std::mutex> lock(mutex_);
            const std::size_t gap = std::min<std::size_t>(
                static_cast<std::size_t>(number) - 2, schedule_.retryDelays.size() - 1);
            if (cv_.wait_for(lock, schedule_.retryDelays.at(gap), [this]() { return !running_; })) {
                break;  // shutting down: the message stays unsent, and says so
            }
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            break;
        }
        bool reachable = false;
        outcome = attempt(task, deadline, reachable);
        if (reachable) {
            // The far side answered. Stored or refused, that is the answer:
            // repeating a refusal only spends the minute the user is waiting.
            return outcome;
        }
    }
    outcome.stored = false;
    outcome.errorCode = std::string(bazarish::toString(ErrorCode::eRecipientServerUnreachable));
    outcome.errorMessage = "the recipient's server could not be reached";
    return outcome;
}

OutboundCourier::Outcome OutboundCourier::attempt(
    const Task& task, const std::chrono::steady_clock::time_point deadline, bool& outReachable)
{
    outReachable = false;
    Outcome outcome;
    const std::chrono::seconds left = std::chrono::duration_cast<std::chrono::seconds>(
        deadline - std::chrono::steady_clock::now());
    const std::chrono::seconds dialFor = std::min(schedule_.dial, left);
    if (dialFor.count() <= 0) {
        return outcome;
    }
    if (task.onPhase) {
        task.onPhase(kPhaseDialing);
    }
    const std::shared_ptr<DeliveryStream> stream = openStream_(task.toDest, dialFor);
    if (!stream) {
        return outcome;
    }
    if (task.onPhase) {
        task.onPhase(kPhaseSending);
    }
    // The watchdog is here for a peer that takes the envelope and goes quiet, not
    // for one that is answering slowly: closing the stream mid-reply turns a
    // delivery the far side has already stored into a failure the user is told
    // about, while the recipient sees the message arrive.
    watch(stream,
        std::max(deadline,
            std::chrono::steady_clock::now() + std::chrono::seconds(kReplyGraceSeconds)));
    FederationDeliverResult reply;
    const std::chrono::steady_clock::time_point wroteAt = std::chrono::steady_clock::now();
    try {
        reply = federationSendDeliver(*stream, task.sealed, task.payload);
    } catch (const std::exception& error) {
        unwatch(stream.get());
        // No answer came back, which is exactly what another attempt is for. How
        // long it took to not come back separates a peer that refused the stream
        // outright from one that took the envelope and then said nothing, and
        // those are not the same problem.
        const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - wroteAt);
        bazarish::log::warn("delivery to {} did not complete after {} ms: {}",
            bazarish::log::redact(task.toDest), waited.count(), error.what());
        return outcome;
    }
    unwatch(stream.get());
    if (reply.delivered && !signedForUs(reply, task.deliveryId)) {
        bazarish::log::warn("delivery to {} was claimed without a valid signature",
            bazarish::log::redact(task.toDest));
        return outcome;  // an unsigned claim is not an answer
    }
    outReachable = true;
    outcome.stored = reply.delivered;
    outcome.errorCode = reply.errorCode;
    outcome.errorMessage = reply.errorMessage;
    return outcome;
}

void OutboundCourier::watch(
    const std::shared_ptr<DeliveryStream>& stream, const std::chrono::steady_clock::time_point deadline)
{
    const std::lock_guard<std::mutex> lock(watchMutex_);
    watched_.emplace_back(stream, deadline);
}

void OutboundCourier::unwatch(const DeliveryStream* const stream)
{
    const std::lock_guard<std::mutex> lock(watchMutex_);
    watched_.erase(std::remove_if(watched_.begin(), watched_.end(),
                       [stream](const auto& entry) {
                           const std::shared_ptr<DeliveryStream> held = entry.first.lock();
                           return !held || held.get() == stream;
                       }),
        watched_.end());
}

void OutboundCourier::watchdogLoop()
{
    while (true) {
        std::unique_lock<std::mutex> lock(watchMutex_);
        if (watchCv_.wait_for(lock, kWatchdogTick, [this]() { return !running_; })) {
            return;
        }
        const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
        for (const auto& entry : watched_) {
            const std::shared_ptr<DeliveryStream> held = entry.first.lock();
            if (held && entry.second <= now) {
                // The peer took the envelope and stopped answering. Closing is
                // what turns that into a failed attempt instead of a wait with
                // no end.
                held->close();
            }
        }
    }
}

}  // namespace bazarish::client
