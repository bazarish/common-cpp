// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace bazarish::client {

// What one delivery leg needs of a stream. An interface rather than
// bazarish::i2p::Stream itself, so the attempt schedule can be exercised over a
// socket pair with no router behind it.
class DeliveryStream {
public:
    virtual ~DeliveryStream() = default;
    virtual void readExact(void* buffer, std::size_t size) = 0;
    virtual void writeAll(const void* data, std::size_t size) = 0;
    // Unblocks a read waiting on a peer that took the envelope and then went
    // quiet. Without it that wait has no end: the stream is open, so nothing
    // below reports an error, and the send would sit unfinished forever.
    virtual void close() = 0;
};

// One send gets four tries inside about a minute, and then it belongs to the
// user again. A client that keeps dialing in the background is a client whose
// message state on screen is a guess.
inline constexpr int kDeliveryAttempts = 4;
// Waits between attempts - one fewer than the attempts, because nothing waits
// after the last one. Widening, because a leaseset a moment from publishing
// needs seconds and a recipient whose router is down needs more than this run
// has to give.
inline constexpr int kDeliveryRetryDelaysSeconds[kDeliveryAttempts - 1] = {2, 4, 8};
// How long one attempt may spend reaching the far side. Short because the
// destination it dials from already has its tunnels: what is left is a leaseset
// lookup and a stream handshake, not a tunnel build.
inline constexpr int kDeliveryDialSeconds = 15;
// The whole run, dials and waits together: 4 * 15 + 2 + 4 + 8 = 74. Enforced as
// a deadline so a peer that accepts the stream and then says nothing cannot
// stretch one send past the minute the user was promised.
inline constexpr int kDeliveryRunSeconds = 75;
// Once the envelope has been written, the far side is going to answer or not -
// and cutting that answer off at the run deadline is how a delivery the
// recipient's server accepted gets reported as one that never arrived. So the
// wait for the reply, and only that wait, may outlive the run by this much.
inline constexpr int kReplyGraceSeconds = 30;

// Phases of one send, in the transport's words. The chip and the activity row
// both read from these, so they cannot disagree about where a message is.
inline constexpr char kPhasePreparing[] = "preparing";
inline constexpr char kPhaseDialing[] = "dialing";
inline constexpr char kPhaseSending[] = "sending";
// A token the recipient's server would not take. Reported as
// "token-refused:<how many are left to try>", built by the session: the message
// is not failing, it is being offered again with another capability.
inline constexpr char kPhaseTokenRefused[] = "token-refused";
// Retries are reported as "retry <n>/<attempts>", built by the courier.
inline constexpr char kPhaseRetryPrefix[] = "retry ";

// The shape of one delivery run. The defaults are the protocol's; a test
// substitutes a faster one so the schedule can be exercised without waiting it
// out.
struct DeliverySchedule {
    int attempts = kDeliveryAttempts;
    std::chrono::seconds dial{kDeliveryDialSeconds};
    std::vector<std::chrono::seconds> retryDelays{
        std::chrono::seconds{kDeliveryRetryDelaysSeconds[0]},
        std::chrono::seconds{kDeliveryRetryDelaysSeconds[1]},
        std::chrono::seconds{kDeliveryRetryDelaysSeconds[2]}};
    std::chrono::seconds run{kDeliveryRunSeconds};
};

// This client's own outbound delivery. There is no server path: an envelope goes
// out over I2P from a destination this client holds for the recipient, and if it
// cannot go, the message fails where the user can see it. The account's own
// server is never asked to dial anyone, so it never learns who is written to.
class OutboundCourier {
public:
    using PhaseFn = std::function<void(const std::string& phase)>;

    struct Outcome {
        // The recipient's server took the envelope and signed for it.
        bool stored = false;
        // Set when the far side answered with a refusal.
        std::string errorCode;
        std::string errorMessage;
    };
    using OutcomeFn = std::function<void(const Outcome& outcome)>;

    // Makes ready the local address this correspondent's mail leaves from
    // (holding one per correspondent) and waits for its tunnels. False when this
    // device has no address to send from. Its wait is deliberately outside the
    // delivery budget below: building tunnels is a local condition, and failing
    // a message for it would blame the recipient for this device's cold start.
    // peerName is what this account calls the correspondent, for the router's
    // status view; empty when there is no name yet.
    using PrepareFn
        = std::function<bool(const std::string& toDest, const std::string& peerName)>;
    // Dials the recipient's destination from that address. Null when the far
    // side cannot be reached inside the timeout.
    using OpenStreamFn = std::function<std::shared_ptr<DeliveryStream>(
        const std::string& toDest, std::chrono::seconds timeout)>;

    struct Task {
        std::string toDest;
        // Read where the contacts are, on the thread that owns them, so the
        // courier's own threads never reach into the session for it.
        std::string peerName;
        Bytes sealed;
        Bytes payload;
        // What the two servers call this delivery. Carried for the log and for
        // the recipient's signed confirmation, which is made over it.
        std::string deliveryId;
        // Both run on a worker thread, not on the thread that submitted.
        PhaseFn onPhase;
        OutcomeFn onOutcome;
    };

    OutboundCourier(PrepareFn prepare, OpenStreamFn openStream, DeliverySchedule schedule = {});
    ~OutboundCourier();

    // Runs the whole schedule on the CALLING thread, for a send whose caller is
    // the one that must answer for it (a contact request).
    Outcome deliverNow(const Task& task);
    // Hands the task to the workers and returns at once. Everything after that
    // arrives through the task's own callbacks.
    void submit(Task task);
    void stop();

private:
    void workerLoop();
    void watchdogLoop();
    // Answers for tasks that will never be run: a send handed in after the
    // courier stopped, or one still queued when it did. Called with the lock
    // released - the callback belongs to the caller, not to this queue.
    void reportDropped(const std::deque<Task>& tasks);
    // One dial and one frame exchange. reachable says whether the far side
    // answered at all - not answering is the only thing worth a second attempt.
    Outcome attempt(const Task& task, std::chrono::steady_clock::time_point deadline,
        bool& outReachable);
    // Closes a stream that is still waiting for a reply past its deadline.
    void watch(const std::shared_ptr<DeliveryStream>& stream,
        std::chrono::steady_clock::time_point deadline);
    void unwatch(const DeliveryStream* stream);

    const PrepareFn prepare_;
    const OpenStreamFn openStream_;
    const DeliverySchedule schedule_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Task> queue_;
    // Destinations a worker is delivering to right now. One at a time per
    // destination, so two messages to one correspondent keep the order they were
    // sent in; different correspondents go in parallel.
    std::set<std::string> busyDests_;
    std::atomic<bool> running_{true};
    std::vector<std::thread> workers_;

    std::mutex watchMutex_;
    std::condition_variable watchCv_;
    std::vector<std::pair<std::weak_ptr<DeliveryStream>, std::chrono::steady_clock::time_point>>
        watched_;
    std::thread watchdog_;
};

}  // namespace bazarish::client
