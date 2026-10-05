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

class DeliveryStream {
public:
    virtual ~DeliveryStream() = default;
    virtual void readExact(void* buffer, std::size_t size) = 0;
    virtual void writeAll(const void* data, std::size_t size) = 0;
    virtual void close() = 0;
};

inline constexpr int kDeliveryAttempts = 4;
inline constexpr int kDeliveryRetryDelaysSeconds[kDeliveryAttempts - 1] = {2, 4, 8};
inline constexpr int kDeliveryDialSeconds = 15;
inline constexpr int kReplyGraceSeconds = 30;
inline constexpr int kDeliveryRunSeconds = []() {
    int total = kDeliveryAttempts * kDeliveryDialSeconds + kReplyGraceSeconds;
    for (const int gap : kDeliveryRetryDelaysSeconds) {
        total += gap;
    }
    return total;
}();

inline constexpr char kPhasePreparing[] = "preparing";
inline constexpr char kPhaseDialing[] = "dialing";
inline constexpr char kPhaseSending[] = "sending";
inline constexpr char kPhaseRetryPrefix[] = "retry ";

struct DeliverySchedule {
    int attempts = kDeliveryAttempts;
    std::chrono::seconds dial{kDeliveryDialSeconds};
    std::vector<std::chrono::seconds> retryDelays{
        std::chrono::seconds{kDeliveryRetryDelaysSeconds[0]},
        std::chrono::seconds{kDeliveryRetryDelaysSeconds[1]},
        std::chrono::seconds{kDeliveryRetryDelaysSeconds[2]}};
    std::chrono::seconds run{kDeliveryRunSeconds};
};

class OutboundCourier {
public:
    using PhaseFn = std::function<void(const std::string& phase)>;

    struct Outcome {
        bool stored = false;
        std::string errorCode;
        std::string errorMessage;
    };
    using OutcomeFn = std::function<void(const Outcome& outcome)>;

    using PrepareFn
        = std::function<bool(const std::string& toDest, const std::string& peerName)>;
    using OpenStreamFn = std::function<std::shared_ptr<DeliveryStream>(
        const std::string& toDest, std::chrono::seconds timeout)>;

    struct Task {
        std::string toDest;
        std::string peerName;
        Bytes sealed;
        Bytes payload;
        std::string deliveryId;
        PhaseFn onPhase;
        OutcomeFn onOutcome;
    };

    OutboundCourier(PrepareFn prepare, OpenStreamFn openStream, DeliverySchedule schedule = {});
    ~OutboundCourier();

    Outcome deliverNow(const Task& task);
    void submit(Task task);
    void stop();

private:
    void workerLoop();
    void watchdogLoop();
    void reportDropped(const std::deque<Task>& tasks);
    Outcome attempt(const Task& task, std::chrono::steady_clock::time_point deadline,
        bool& outReachable, bool& outSent);
    void watch(const std::shared_ptr<DeliveryStream>& stream,
        std::chrono::steady_clock::time_point deadline);
    void unwatch(const DeliveryStream* stream);

    const PrepareFn prepare_;
    const OpenStreamFn openStream_;
    const DeliverySchedule schedule_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Task> queue_;
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
