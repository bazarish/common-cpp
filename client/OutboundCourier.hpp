// Bazarish project (c) 2026
#pragma once

#include "PresenceSeed.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Epochs.hpp>
#include <bazarish/I2p.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace bazarish::client {

class DeliveryStream {
public:
    virtual ~DeliveryStream() = default;
    virtual std::size_t readSome(ByteBuffer buffer) = 0;
    virtual void writeAll(ByteView data) = 0;
    virtual void close() = 0;
};

inline constexpr int kDeliveryDialSeconds = 15;
inline constexpr int kReplyGraceSeconds = 30;
// The slowest a delivery stream is still expected to move; a big payload gets this much longer.
inline constexpr std::size_t kSlowestDeliveryBytesPerSecond = 8 * 1024;
// i2pd ends a lease 10 minutes after its tunnel was built.
inline constexpr std::chrono::seconds kLeaseLifetime{600};
// The clock difference NTCP2 and SSU2 accept between two routers.
inline constexpr std::chrono::seconds kRouterClockSkew{60};
// By then a lease set that was current at a failed attempt has expired everywhere.
inline constexpr std::chrono::seconds kStaleLeaseSetBound = kLeaseLifetime + kRouterClockSkew;

inline constexpr char kPhasePreparing[] = "preparing";
inline constexpr char kPhaseDialing[] = "dialing";
inline constexpr char kPhaseSending[] = "sending";
inline constexpr char kPhaseWaiting[] = "waiting";

inline constexpr char kWithdrawnMessage[] = "its recipient was removed before it was delivered";

// No destination is an empty host, so the account's own mailbox cannot collide with one.
inline constexpr char kOwnMailboxRoute[] = "";

inline constexpr std::size_t kDeliveryWorkers = 4;

struct CourierTimings {
    std::chrono::seconds dial{kDeliveryDialSeconds};
    std::chrono::seconds reply{kReplyGraceSeconds};
    std::chrono::seconds staleBound{kStaleLeaseSetBound};
    // The epoch a letter is sealed to is the one current by this clock at each attempt.
    UtcClock utcNow = systemUtcSeconds;
};

struct DeliveryOutcome {
    bool stored = false;
    std::string errorCode;
    std::string errorMessage;
};

struct DeliveryWatch {
    std::function<void(const std::string& phase)> onPhase;
    std::function<void(const DeliveryOutcome& outcome)> onOutcome;
};

struct Letter {
    std::uint64_t seq = 0;
    // The recipient's serving destination, or kOwnMailboxRoute.
    std::string route;
    std::string peerName;
    std::string mailbox;
    std::string deliveryClass;
    std::string deliveryId;
    Bytes pass;
    Bytes servingSealingDer;
    Bytes plain;
    std::vector<EpochPublic> sealTo;
    // Set on a letter to one of the account's own devices: sealed to that device's key instead.
    std::string toDevice;
    Bytes deviceSealingDer;
    Bytes payload;
    std::string kind;
    // UTC milliseconds; zero for a letter that stays current.
    std::int64_t notAfterMs = 0;
};

class OutboundCourier {
public:
    using Outcome = DeliveryOutcome;
    using PhaseFn = std::function<void(const std::string& phase)>;
    using OutcomeFn = std::function<void(const Outcome& outcome)>;
    using SettledFn = std::function<void(std::uint64_t seq, const Outcome& outcome)>;

    struct Links {
        std::function<bool(const std::string& toDest, const std::string& peerName)> prepare;
        std::function<std::shared_ptr<DeliveryStream>(
            const std::string& toDest, std::chrono::seconds timeout)>
            openStream;
        // None when the router cannot look past what it holds.
        std::function<std::optional<i2p::LeaseSetRefresh>(const std::string& toDest)> lookup;
        std::function<void(const std::string& toDest)> keepOwn;
        std::function<void(const std::string& toDest)> release;
        // None when the server did not answer.
        std::function<std::optional<Outcome>(const Letter& letter)> ownMailbox;
    };

    explicit OutboundCourier(Links links, SettledFn settled = {}, CourierTimings timings = {},
        std::size_t workers = kDeliveryWorkers);
    ~OutboundCourier();
    OutboundCourier(const OutboundCourier&) = delete;
    OutboundCourier& operator=(const OutboundCourier&) = delete;

    void submit(Letter letter, DeliveryWatch watch = {});
    // Watches run on the courier's threads; a settled letter not yet forgotten tells its outcome.
    bool attach(std::uint64_t seq, DeliveryWatch watch);
    void forget(std::uint64_t seq);
    // Something came from the route: a closed gate looks the lease set up, our mailbox opens.
    void heard(const std::string& route);
    void readdress(
        const std::string& mailbox, const std::string& toDest, const Bytes& servingSealingDer);
    // A letter that found no current epoch of its recipient waits for this.
    void rekey(const std::string& mailbox, const std::vector<EpochPublic>& epochs);
    void withdraw(const std::string& mailbox);
    // What is still on its way is not reported: the outbox keeps it.
    void stop();

private:
    struct Held {
        Letter letter;
        std::vector<DeliveryWatch> watches;
        std::string phase;
        bool started = false;
        bool inFlight = false;
        bool withdrawn = false;
        bool keyless = false;
    };

    struct Gate {
        bool busy = false;
        bool closed = false;
        bool lookupDue = false;
        bool failedSeenKnown = false;
        std::optional<i2p::LeaseSetSeen> failedSeen;
        std::chrono::steady_clock::time_point opensAt;
    };

    enum class JobKind { eAttempt, eLookup };

    struct Job {
        JobKind kind = JobKind::eAttempt;
        std::string route;
        Letter letter;
        bool keepOwn = false;
    };

    struct Notice {
        DeliveryWatch watch;
        std::string phase;
        std::optional<Outcome> outcome;
    };

    struct Settled {
        std::uint64_t seq = 0;
        Outcome outcome;
        std::vector<DeliveryWatch> watches;
        std::string route;
        bool releaseOwn = false;
    };

    enum class Answer { eAnswered, eUnanswered, eKeyless };

    void workerLoop();
    std::optional<Job> pickLocked();
    void openDueLocked(std::chrono::steady_clock::time_point now);
    void expireLocked(std::int64_t nowMs, std::vector<Settled>& out);
    std::optional<std::chrono::steady_clock::time_point> nextDueLocked() const;
    Settled settleLocked(std::map<std::uint64_t, Held>::iterator held, const Outcome& outcome);
    void finish(std::vector<Settled> settled);
    static void tell(const std::vector<Notice>& notices);
    void runAttempt(const Job& job);
    void runLookup(const Job& job);
    Answer attempt(const Letter& letter, Outcome& outcome);
    Answer attemptFederation(const Letter& letter, Outcome& outcome);
    std::vector<std::pair<DeliveryWatch, std::string>> closeGateLocked(const std::string& route);
    void phase(std::uint64_t seq, const std::string& phase);
    void carryReturned();
    void watch(const std::shared_ptr<DeliveryStream>& stream,
        std::chrono::steady_clock::time_point deadline);
    void unwatch(const std::shared_ptr<DeliveryStream>& stream);
    void watchdogLoop(const std::stop_token& stop);

    const Links links_;
    const SettledFn settled_;
    const CourierTimings timings_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::map<std::uint64_t, Held> letters_;
    std::map<std::uint64_t, Outcome> settledOutcomes_;
    std::vector<Notice> notices_;
    std::vector<Settled> withdrawn_;
    std::map<std::string, Gate> gates_;
    bool running_ = true;
    std::vector<std::thread> workers_;

    std::mutex watchMutex_;
    std::condition_variable_any watchCv_;
    std::vector<std::pair<std::weak_ptr<DeliveryStream>, std::chrono::steady_clock::time_point>>
        watched_;
    std::jthread watchdog_;
    std::unique_ptr<i2p::CarryWatch> carry_;
};

}  // namespace bazarish::client
