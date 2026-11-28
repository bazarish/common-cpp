// Bazarish project (c) 2026
#include "OutboundCourier.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/DeliveryEnvelope.hpp>
#include <bazarish/Devices.hpp>
#include <bazarish/FederationFrame.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/StopWake.hpp>

#include <algorithm>
#include <exception>
#include <iterator>
#include <set>
#include <stdexcept>

namespace bazarish::client {

namespace {

constexpr std::chrono::seconds kWatchdogTick{1};
constexpr std::size_t kTracedWriteBytes = 16 * 1024;
constexpr std::size_t kLineEndBytes = 1;

using Clock = std::chrono::steady_clock;

std::int64_t millisSince(const Clock::time_point from, const Clock::time_point to)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(to - from).count();
}

class TracedStream final : public DeliveryStream {
public:
    explicit TracedStream(DeliveryStream& stream)
        : stream_(stream)
    {
    }

    std::size_t readSome(const ByteBuffer buffer) override
    {
        if (!waiting_) {
            waiting_ = true;
            waitingAt_ = Clock::now();
        }
        const std::size_t got = stream_.readSome(buffer);
        read_ += got;
        return got;
    }

    void writeAll(const ByteView data) override
    {
        for (std::size_t at = 0; at < data.size(); at += kTracedWriteBytes) {
            const std::size_t size = std::min(kTracedWriteBytes, data.size() - at);
            stream_.writeAll(data.subspan(at, size));
            taken_ += size;
            takenAt_ = Clock::now();
        }
    }

    void close() override { stream_.close(); }

    bool answered() const override { return stream_.answered(); }

    std::string where(const std::size_t whole) const
    {
        const Clock::time_point now = Clock::now();
        std::string told = "the stream took " + std::to_string(taken_) + " of "
            + std::to_string(whole) + " bytes";
        if (taken_ > 0) {
            told += ", the last " + std::to_string(millisSince(takenAt_, now)) + " ms ago";
        }
        if (!waiting_) {
            return told + "; no reply was awaited yet";
        }
        return told + "; the reply was awaited for " + std::to_string(millisSince(waitingAt_, now))
            + " ms and " + std::to_string(read_) + " bytes of it came";
    }

private:
    DeliveryStream& stream_;
    std::size_t taken_ = 0;
    Clock::time_point takenAt_{};
    bool waiting_ = false;
    Clock::time_point waitingAt_{};
    std::size_t read_ = 0;
};
constexpr char kExpiredMessage[] = "it was no longer current when its recipient could be reached";

bool signedForUs(const FederationDeliverResult& reply, const std::string& deliveryId)
{
    if (reply.deliveryId != deliveryId || reply.signature.empty()) {
        return false;
    }
    const Bytes signedBytes = deliveryAckInput(deliveryId);
    try {
        return bazarish::verify(
            Key::fromPublicDer(reply.signerPublicDer), signedBytes, reply.signature);
    } catch (const std::exception& error) {
        bazarish::log::warn("a delivery confirmation did not verify: {}", error.what());
        return false;
    }
}

std::int64_t utcMillisNow()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Federation.md: every contact request leaves from an address that carried nothing before it.
bool leavesFromItsOwnAddress(const Letter& letter)
{
    return letter.deliveryClass == kContactDeliveryClass;
}

std::string routeName(const std::string& route)
{
    return route == kOwnMailboxRoute ? std::string("this account's mailbox")
                                     : bazarish::log::redact(route);
}

}  // namespace

OutboundCourier::OutboundCourier(
    Links links, SettledFn settled, const CourierTimings timings, const std::size_t workers)
    : links_(std::move(links))
    , settled_(std::move(settled))
    , timings_(timings)
{
    watchdog_ = std::jthread([this](const std::stop_token& stop) { watchdogLoop(stop); });
    for (std::size_t i = 0; i < workers; ++i) {
        workers_.emplace_back(&OutboundCourier::workerLoop, this);
    }
    carry_ = std::make_unique<i2p::CarryWatch>([this]() { carryReturned(); });
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
    }
    carry_.reset();
    cv_.notify_all();
    watchdog_.request_stop();
    std::vector<std::shared_ptr<DeliveryStream>> carrying;
    {
        const std::lock_guard<std::mutex> lock(watchMutex_);
        for (const auto& entry : watched_) {
            if (std::shared_ptr<DeliveryStream> held = entry.first.lock()) {
                carrying.push_back(std::move(held));
            }
        }
    }
    for (const std::shared_ptr<DeliveryStream>& stream : carrying) {
        stream->close();
    }
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

void OutboundCourier::submit(Letter letter, DeliveryWatch watch)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            throw std::runtime_error("this device stopped sending before the message left");
        }
        const std::uint64_t seq = letter.seq;
        if (letters_.count(seq) != 0) {
            throw std::logic_error("a letter is handed to the courier once");
        }
        const auto gate = gates_.find(letter.route);
        Held held;
        held.letter = std::move(letter);
        if (gate != gates_.end() && gate->second.closed) {
            held.phase = gate->second.awaitsServer ? kPhaseOffline : kPhaseWaiting;
            if (watch.onPhase) {
                notices_.push_back(Notice{watch, held.phase, std::nullopt});
            }
        }
        if (watch.onPhase || watch.onOutcome) {
            held.watches.push_back(watch);
        }
        letters_.emplace(seq, std::move(held));
    }
    cv_.notify_all();
}

bool OutboundCourier::attach(const std::uint64_t seq, DeliveryWatch watch)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto held = letters_.find(seq);
        if (held != letters_.end()) {
            held->second.watches.push_back(watch);
            if (!held->second.phase.empty() && watch.onPhase) {
                notices_.push_back(Notice{watch, held->second.phase, std::nullopt});
            }
        } else if (const auto told = settledOutcomes_.find(seq); told != settledOutcomes_.end()) {
            if (watch.onOutcome) {
                notices_.push_back(Notice{watch, {}, told->second});
            }
        } else {
            return false;
        }
    }
    cv_.notify_all();
    return true;
}

void OutboundCourier::tell(const std::vector<Notice>& notices)
{
    for (const Notice& notice : notices) {
        if (notice.outcome.has_value()) {
            notice.watch.onOutcome(*notice.outcome);
        } else {
            notice.watch.onPhase(notice.phase);
        }
    }
}

void OutboundCourier::forget(const std::uint64_t seq)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    settledOutcomes_.erase(seq);
}

void OutboundCourier::heard(const std::string& route)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (route == kOwnMailboxRoute) {
            bool opened = false;
            for (auto& [gated, gate] : gates_) {
                if (gate.closed && (gate.awaitsServer || gated == kOwnMailboxRoute)) {
                    gate.closed = false;
                    gate.awaitsServer = false;
                    opened = true;
                }
            }
            if (!opened) {
                return;
            }
            bazarish::log::info("our server answered: what waits in the outbox goes");
        } else {
            const auto gate = gates_.find(route);
            if (gate == gates_.end() || !gate->second.closed || !links_.lookup
                || gate->second.lookupDue) {
                return;
            }
            gate->second.lookupDue = true;
        }
    }
    cv_.notify_all();
}

void OutboundCourier::unreachable(const std::string& route)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto gate = gates_.find(route);
        if (route == kOwnMailboxRoute || (gate != gates_.end() && gate->second.closed)) {
            return;
        }
        for (const auto& [watch, phase] : closeGateLocked(route, false)) {
            if (watch.onPhase) {
                notices_.push_back(Notice{watch, phase, std::nullopt});
            }
        }
    }
    cv_.notify_all();
}

void OutboundCourier::readdress(
    const std::string& mailbox, const std::string& toDest, const Bytes& servingSealingDer)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [seq, held] : letters_) {
            if (held.letter.mailbox == mailbox && held.letter.route != kOwnMailboxRoute) {
                held.letter.route = toDest;
                held.letter.servingSealingDer = servingSealingDer;
            }
        }
    }
    cv_.notify_all();
}

void OutboundCourier::rekey(const std::string& mailbox, const std::vector<EpochPublic>& epochs)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [seq, held] : letters_) {
            if (held.letter.mailbox == mailbox) {
                held.letter.sealTo = epochs;
                held.keyless = false;
            }
        }
    }
    cv_.notify_all();
}

void OutboundCourier::exchanged(const std::string& mailbox, const std::int64_t utcSeconds)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [seq, held] : letters_) {
        if (held.letter.mailbox == mailbox && held.letter.route != kOwnMailboxRoute) {
            held.letter.exchangedAt = std::max(held.letter.exchangedAt, utcSeconds);
        }
    }
}

void OutboundCourier::withdraw(const std::string& mailbox)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        Outcome withdrawn;
        withdrawn.reason = NotStored::eWithdrawn;
        withdrawn.errorMessage = kWithdrawnMessage;
        for (auto held = letters_.begin(); held != letters_.end();) {
            const auto next = std::next(held);
            if (held->second.letter.mailbox == mailbox
                && held->second.letter.route != kOwnMailboxRoute) {
                if (held->second.inFlight) {
                    held->second.withdrawn = true;
                } else {
                    withdrawn_.push_back(settleLocked(held, withdrawn));
                }
            }
            held = next;
        }
    }
    cv_.notify_all();
}

bool OutboundCourier::withdrawLetter(const std::uint64_t seq)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto held = letters_.find(seq);
        if (held == letters_.end()) {
            const auto settled = settledOutcomes_.find(seq);
            return settled == settledOutcomes_.end() || !settled->second.stored;
        }
        if (held->second.inFlight) {
            held->second.withdrawn = true;
            return false;
        }
        held->second.watches.clear();
        Outcome withdrawn;
        withdrawn.reason = NotStored::eWithdrawn;
        withdrawn.errorMessage = kWithdrawnMessage;
        withdrawn_.push_back(settleLocked(held, withdrawn));
    }
    cv_.notify_all();
    return true;
}

void OutboundCourier::carryReturned()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    bool held = false;
    for (auto& [route, gate] : gates_) {
        if (gate.closed) {
            gate.awaitsServer = true;
            gate.lookupDue = false;
            held = true;
        }
    }
    if (held) {
        bazarish::log::info("the link came back: what waits goes once our server answers");
    }
}

void OutboundCourier::recheckDueLocked(const std::chrono::steady_clock::time_point now)
{
    for (auto& [route, gate] : gates_) {
        if (!gate.closed || gate.awaitsServer || route == kOwnMailboxRoute || gate.recheckAt > now) {
            continue;
        }
        gate.recheckAt = now + timings_.recheck;
        if (links_.lookup && !gate.lookupBlind) {
            gate.lookupDue = true;
            continue;
        }
        gate.closed = false;
        bazarish::log::info("{}: no lease set lookup here, trying again", routeName(route));
    }
}

void OutboundCourier::expireLocked(const std::int64_t nowMs, std::vector<Settled>& out)
{
    Outcome expired;
    expired.reason = NotStored::eExpired;
    expired.errorMessage = kExpiredMessage;
    for (auto held = letters_.begin(); held != letters_.end();) {
        const auto next = std::next(held);
        const Letter& letter = held->second.letter;
        if (!held->second.inFlight && letter.notAfterMs != 0 && letter.notAfterMs <= nowMs) {
            bazarish::log::info("a {} to {} went out of date before it could be delivered",
                letter.kind, routeName(letter.route));
            out.push_back(settleLocked(held, expired));
        }
        held = next;
    }
}

std::optional<std::chrono::steady_clock::time_point> OutboundCourier::nextDueLocked() const
{
    std::optional<std::chrono::steady_clock::time_point> due;
    const auto sooner = [&due](const std::chrono::steady_clock::time_point at) {
        if (!due.has_value() || at < *due) {
            due = at;
        }
    };
    for (const auto& [route, gate] : gates_) {
        if (gate.closed && !gate.awaitsServer && route != kOwnMailboxRoute) {
            sooner(gate.recheckAt);
        }
    }
    const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    const std::int64_t nowMs = utcMillisNow();
    for (const auto& [seq, held] : letters_) {
        if (held.letter.notAfterMs != 0 && !held.inFlight) {
            sooner(now
                + std::chrono::milliseconds(
                    std::max<std::int64_t>(0, held.letter.notAfterMs - nowMs)));
        }
    }
    return due;
}

std::optional<OutboundCourier::Job> OutboundCourier::pickLocked()
{
    std::set<std::string> seen;
    for (auto& [seq, held] : letters_) {
        const std::string& route = held.letter.route;
        if (held.keyless && !epochFor(held.letter.sealTo, timings_.utcNow()).has_value()) {
            const auto gate = gates_.find(route);
            if (gate != gates_.end() && gate->second.closed && gate->second.lookupDue
                && !gate->second.busy) {
                gate->second.lookupDue = false;
                gate->second.busy = true;
                Job job;
                job.route = route;
                job.kind = JobKind::eLookup;
                return job;
            }
            continue;
        }
        if (!seen.insert(route).second) {
            continue;
        }
        Gate& gate = gates_[route];
        if (gate.busy) {
            continue;
        }
        Job job;
        job.route = route;
        if (gate.closed) {
            if (!gate.lookupDue) {
                continue;
            }
            gate.lookupDue = false;
            gate.busy = true;
            job.kind = JobKind::eLookup;
            return job;
        }
        gate.busy = true;
        job.kind = JobKind::eAttempt;
        job.letter = held.letter;
        job.keepOwn = leavesFromItsOwnAddress(held.letter) && !held.started;
        held.started = true;
        held.inFlight = true;
        return job;
    }
    return std::nullopt;
}

OutboundCourier::Settled OutboundCourier::settleLocked(
    const std::map<std::uint64_t, Held>::iterator held, const Outcome& outcome)
{
    Settled settled;
    settled.seq = held->first;
    settled.outcome = outcome;
    settled.watches = std::move(held->second.watches);
    settled.route = held->second.letter.route;
    settled.releaseOwn = leavesFromItsOwnAddress(held->second.letter) && held->second.started;
    settledOutcomes_[held->first] = outcome;
    letters_.erase(held);
    return settled;
}

void OutboundCourier::finish(std::vector<Settled> settled)
{
    for (const Settled& done : settled) {
        if (done.releaseOwn && links_.release) {
            links_.release(done.route);
        }
        for (const DeliveryWatch& watch : done.watches) {
            if (watch.onOutcome) {
                watch.onOutcome(done.outcome);
            }
        }
        if (settled_) {
            settled_(done.seq, done.outcome);
        }
    }
}

void OutboundCourier::workerLoop()
{
    while (true) {
        std::optional<Job> job;
        std::vector<Settled> expired;
        std::vector<Notice> notices;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            while (running_) {
                notices.swap(notices_);
                if (!notices.empty()) {
                    break;
                }
                recheckDueLocked(std::chrono::steady_clock::now());
                expired.swap(withdrawn_);
                expireLocked(utcMillisNow(), expired);
                if (!expired.empty()) {
                    break;
                }
                job = pickLocked();
                if (job.has_value()) {
                    break;
                }
                const std::optional<std::chrono::steady_clock::time_point> due = nextDueLocked();
                if (due.has_value()) {
                    cv_.wait_until(lock, *due);
                } else {
                    cv_.wait(lock);
                }
            }
            if (!running_) {
                return;
            }
        }
        tell(notices);
        finish(std::move(expired));
        if (!job.has_value()) {
            continue;
        }
        if (job->kind == JobKind::eLookup) {
            runLookup(*job);
        } else {
            runAttempt(*job);
        }
    }
}

void OutboundCourier::phase(const std::uint64_t seq, const std::string& phase)
{
    std::vector<DeliveryWatch> watches;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto held = letters_.find(seq);
        if (held == letters_.end()) {
            return;
        }
        held->second.phase = phase;
        watches = held->second.watches;
    }
    for (const DeliveryWatch& watch : watches) {
        if (watch.onPhase) {
            watch.onPhase(phase);
        }
    }
}

// A failure of our own link says nothing of the recipient: the gate opens once our server answers.
std::vector<std::pair<DeliveryWatch, std::string>> OutboundCourier::closeGateLocked(
    const std::string& route, const bool ownLink)
{
    Gate& gate = gates_[route];
    gate.closed = true;
    gate.recheckAt = std::chrono::steady_clock::now() + timings_.recheck;
    gate.lookupDue = !ownLink && route != kOwnMailboxRoute && static_cast<bool>(links_.lookup);
    gate.awaitsServer = ownLink;
    gate.lookupBlind = false;
    gate.failedSeenKnown = false;
    gate.failedSeen.reset();
    std::vector<std::pair<DeliveryWatch, std::string>> told;
    for (auto& [seq, held] : letters_) {
        if (held.letter.route != route) {
            continue;
        }
        held.phase = ownLink ? kPhaseOffline : kPhaseWaiting;
        for (const DeliveryWatch& watch : held.watches) {
            told.emplace_back(watch, held.phase);
        }
    }
    return told;
}

void OutboundCourier::runAttempt(const Job& job)
{
    if (job.keepOwn && links_.keepOwn) {
        links_.keepOwn(job.route);
    }
    Outcome outcome;
    const std::uint64_t lossesBefore = i2p::linkLosses();
    const std::uint64_t movesBefore = i2p::networkChanges();
    const Answer answer = attempt(job.letter, outcome);
    const bool moved = i2p::networkChanges() != movesBefore;
    const bool ownLink = answer == Answer::eUnprepared || i2p::linkLosses() != lossesBefore
        || i2p::transportState() != i2p::TransportState::eUp;
    std::vector<Settled> settled;
    std::vector<std::pair<DeliveryWatch, std::string>> waiting;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        gates_[job.route].busy = false;
        const auto held = letters_.find(job.letter.seq);
        if (held != letters_.end()) {
            held->second.inFlight = false;
            if (answer == Answer::eAnswered) {
                settled.push_back(settleLocked(held, outcome));
            } else if (held->second.withdrawn) {
                Outcome withdrawn;
                withdrawn.reason = NotStored::eWithdrawn;
                withdrawn.errorMessage = kWithdrawnMessage;
                settled.push_back(settleLocked(held, withdrawn));
            } else if (answer == Answer::eKeyless) {
                held->second.keyless = true;
                held->second.phase = kPhaseWaiting;
                for (const DeliveryWatch& watch : held->second.watches) {
                    waiting.emplace_back(watch, held->second.phase);
                }
                bazarish::log::warn("a {} to {} waits: this device holds no current key of its"
                                    " recipient", job.letter.kind, routeName(job.route));
            } else if (moved && !ownLink) {
                bazarish::log::info("{} was not reached while this device moved network:"
                                    " sending again", routeName(job.route));
            } else if (held->second.letter.route == job.route && ownLink) {
                waiting = closeGateLocked(job.route, true);
                bazarish::log::warn("{} was not reached: this device {}; what waits for it goes"
                                    " when our server answers",
                    routeName(job.route),
                    answer == Answer::eUnprepared ? "has no address with tunnels to send from"
                                                  : "lost its own link");
            } else if (answer == Answer::eBroken) {
                bazarish::log::info("{} answered and the stream broke: sending again",
                    routeName(job.route));
            } else if (held->second.letter.route == job.route) {
                waiting = closeGateLocked(job.route, false);
                bazarish::log::warn("{} did not answer: what waits for it goes {}",
                    routeName(job.route),
                    job.route == kOwnMailboxRoute ? "when our server answers"
                                                  : "on a newer lease set, looked up every "
                            + std::to_string(timings_.recheck.count()) + " s");
            }
        }
    }
    cv_.notify_all();
    for (const auto& [watch, phase] : waiting) {
        if (watch.onPhase) {
            watch.onPhase(phase);
        }
    }
    finish(std::move(settled));
}

void OutboundCourier::runLookup(const Job& job)
{
    std::optional<i2p::LeaseSetRefresh> found;
    try {
        found = links_.lookup(job.route);
    } catch (const std::exception& error) {
        bazarish::log::warn(
            "the lease set of {} was not looked up: {}", routeName(job.route), error.what());
    }
    bool newer = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        Gate& gate = gates_[job.route];
        gate.busy = false;
        gate.lookupBlind = !found.has_value();
        if (gate.closed && found.has_value()) {
            if (!gate.failedSeenKnown) {
                gate.failedSeen = found->before;
                gate.failedSeenKnown = true;
            }
            if (found->after.has_value() && i2p::publishedLater(*found->after, gate.failedSeen)) {
                gate.closed = false;
                gate.awaitsServer = false;
                newer = true;
                bazarish::log::info(
                    "{} published a newer lease set: trying again", routeName(job.route));
            } else {
                bazarish::log::info("{} holds the lease set of the failed attempt: waiting",
                    routeName(job.route));
            }
        }
    }
    cv_.notify_all();
    if (newer && links_.newerLeaseSet) {
        links_.newerLeaseSet(job.route);
    }
}

OutboundCourier::Answer OutboundCourier::attempt(const Letter& plainLetter, Outcome& outcome)
{
    Letter letter = plainLetter;
    if (!letter.toDevice.empty()) {
        try {
            letter.payload = hybrid::seal(
                letter.plain, Key::fromPublicDer(letter.deviceSealingDer), deviceKid(letter.toDevice));
        } catch (const std::exception& error) {
            outcome.reason = NotStored::eNotSealed;
            outcome.errorMessage = std::string("the device's key does not seal: ") + error.what();
            return Answer::eAnswered;
        }
    } else {
        const std::int64_t now = timings_.utcNow();
        const std::optional<EpochPublic> epoch = epochFor(plainLetter.sealTo, now);
        if (!epoch.has_value()) {
            return Answer::eKeyless;
        }
        outcome.carriedRouting
            = !letter.plainWithRouting.empty() && now - letter.exchangedAt > kExchangeGapSeconds;
        try {
            letter.payload = sealToEpoch(outcome.carriedRouting ? letter.plainWithRouting : letter.plain, *epoch);
        } catch (const std::exception& error) {
            outcome.reason = NotStored::eNotSealed;
            outcome.errorMessage
                = std::string("the recipient's epoch key does not seal: ") + error.what();
            return Answer::eAnswered;
        }
    }
    if (letter.route != kOwnMailboxRoute) {
        return attemptFederation(letter, outcome);
    }
    phase(letter.seq, kPhaseSending);
    std::optional<Outcome> told;
    try {
        told = links_.ownMailbox(letter);
    } catch (const std::exception& error) {
        bazarish::log::warn(
            "this account's mailbox did not take a {}: {}", letter.kind, error.what());
    }
    if (!told.has_value()) {
        return Answer::eUnanswered;
    }
    outcome = *told;
    return Answer::eAnswered;
}

OutboundCourier::Answer OutboundCourier::attemptFederation(const Letter& letter, Outcome& outcome)
{
    const std::string& toDest = letter.route;
    Bytes sealed;
    try {
        sealed = sealDeliveryEnvelope(
            DeliveryEnvelope{letter.deliveryClass, letter.mailbox, letter.deliveryId,
                letter.pass.empty() ? std::nullopt : std::optional<Bytes>(letter.pass)},
            Key::fromPublicDer(letter.servingSealingDer));
    } catch (const std::exception& error) {
        outcome.reason = NotStored::eNotSealed;
        outcome.errorMessage
            = std::string("the recipient's address key does not seal: ") + error.what();
        return Answer::eAnswered;
    }
    phase(letter.seq, kPhasePreparing);
    bool ready = false;
    try {
        ready = links_.prepare(toDest, letter.peerName);
    } catch (const std::exception& error) {
        bazarish::log::warn("no address to send to {} from: {}", routeName(toDest), error.what());
    }
    if (!ready) {
        return Answer::eUnprepared;
    }
    phase(letter.seq, kPhaseDialing);
    std::shared_ptr<DeliveryStream> stream;
    try {
        stream = links_.openStream(toDest, timings_.dial);
    } catch (const std::exception& error) {
        bazarish::log::warn("no stream to {}: {}", routeName(toDest), error.what());
    }
    if (!stream) {
        return Answer::eUnanswered;
    }
    phase(letter.seq, kPhaseSending);
    const std::chrono::seconds carrying(static_cast<std::int64_t>(
        (sealed.size() + letter.payload.size()) / kSlowestDeliveryBytesPerSecond));
    watch(stream, std::chrono::steady_clock::now() + timings_.reply + carrying);
    const std::chrono::steady_clock::time_point wroteAt = std::chrono::steady_clock::now();
    FederationDeliverResult reply;
    TracedStream traced(*stream);
    try {
        reply = federationSendDeliver(traced, sealed, letter.payload);
    } catch (const std::exception& error) {
        unwatch(stream);
        bazarish::log::warn("delivery to {} did not complete after {} ms: {}; {}", routeName(toDest),
            millisSince(wroteAt, Clock::now()), error.what(),
            traced.where(buildFederationDeliverHeader(sealed, letter.payload.size()).size()
                + kLineEndBytes + letter.payload.size()));
        return stream->answered() ? Answer::eBroken : Answer::eUnanswered;
    }
    unwatch(stream);
    if (reply.delivered && !signedForUs(reply, letter.deliveryId)) {
        bazarish::log::warn(
            "delivery to {} was claimed without a valid signature", routeName(toDest));
        return Answer::eUnanswered;
    }
    outcome.stored = reply.delivered;
    outcome.errorCode = reply.errorCode;
    outcome.errorMessage = reply.errorMessage;
    return Answer::eAnswered;
}

void OutboundCourier::watch(const std::shared_ptr<DeliveryStream>& stream,
    const std::chrono::steady_clock::time_point deadline)
{
    const std::lock_guard<std::mutex> lock(watchMutex_);
    watched_.emplace_back(stream, deadline);
}

void OutboundCourier::unwatch(const std::shared_ptr<DeliveryStream>& stream)
{
    const std::lock_guard<std::mutex> lock(watchMutex_);
    watched_.erase(std::remove_if(watched_.begin(), watched_.end(),
                       [&stream](const auto& entry) {
                           const std::shared_ptr<DeliveryStream> held = entry.first.lock();
                           return !held || held == stream;
                       }),
        watched_.end());
}

void OutboundCourier::watchdogLoop(const std::stop_token& stop)
{
    const StopWake wake(stop, watchMutex_, watchCv_);
    std::unique_lock<std::mutex> lock(watchMutex_);
    const auto stopping = [&stop]() { return stop.stop_requested(); };
    while (!watchCv_.wait_for(lock, stop, kWatchdogTick, stopping)) {
        const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
        for (const auto& entry : watched_) {
            const std::shared_ptr<DeliveryStream> held = entry.first.lock();
            if (held && entry.second <= now) {
                held->close();
            }
        }
    }
}

}  // namespace bazarish::client
