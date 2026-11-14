// Bazarish project (c) 2026
#pragma once

#include "OutboundCourier.hpp"

#include <bazarish/I2p.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string_view>
#include <utility>

namespace bazarish::client {

enum class MailWaitCause {
    eStopped,
    eHeldWaitBroke,
    eLinkBack,
    eServerAnswered,
    eRegistered,
    eNewerLeaseSet,
    eStaleLeaseSet,
    eServerPauseOver,
};

// Nothing tells a client that the server behind a facade is back: it asks at these pauses.
inline constexpr std::chrono::seconds kServerDownFirstPause{1};
inline constexpr std::chrono::seconds kServerDownSecondPause{5};
inline constexpr std::chrono::seconds kServerDownSteadyPause{10};

struct ServerDownPauses {
    std::chrono::milliseconds first{kServerDownFirstPause};
    std::chrono::milliseconds second{kServerDownSecondPause};
    std::chrono::milliseconds steady{kServerDownSteadyPause};
};

inline std::string_view mailWaitCauseName(const MailWaitCause cause)
{
    switch (cause) {
        case MailWaitCause::eStopped: return "stopped";
        case MailWaitCause::eHeldWaitBroke: return "a held wait broke";
        case MailWaitCause::eLinkBack: return "the link came back";
        case MailWaitCause::eServerAnswered: return "our server answered another request";
        case MailWaitCause::eRegistered: return "this device was registered again";
        case MailWaitCause::eNewerLeaseSet: return "the facade published a newer lease set";
        case MailWaitCause::eStaleLeaseSet: return "the lease set of the failed ask has expired";
        case MailWaitCause::eServerPauseOver:
            return "the pause after the facade found its server down is over";
    }
    return "unknown";
}

// What a mail wait that failed waits for before it asks again; a period only after a 502.
class MailWaitGate {
public:
    explicit MailWaitGate(const std::chrono::milliseconds staleBound = kStaleLeaseSetBound,
        const ServerDownPauses serverDownPauses = ServerDownPauses())
        : staleBound_(staleBound)
        , serverDownPauses_(serverDownPauses)
        , carry_([this]() { wake(); })
    {
    }

    MailWaitGate(const MailWaitGate&) = delete;
    MailWaitGate& operator=(const MailWaitGate&) = delete;

    void serverAnswered()
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            serverAnswered_ = true;
        }
        changed_.notify_all();
    }

    void registered()
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            registered_ = true;
        }
        changed_.notify_all();
    }

    void stop()
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            stopped_ = true;
        }
        changed_.notify_all();
    }

    void restart()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = false;
        armed_ = false;
        lastAnswered_ = false;
        reasking_ = false;
        serverDownNext_ = ServerDownPause::eFirst;
    }

    // An ask begins: whatever happened before it is no cause to ask once more.
    void asking()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        followsAnswer_ = lastAnswered_;
        lastAnswered_ = false;
        serverAnswered_ = false;
        registered_ = false;
        carryAtAsk_ = i2p::carryReturns();
    }

    // Called on the waiting thread each time the mail wait is answered.
    void onAnswered(std::function<void()> tell)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        onAnswered_ = std::move(tell);
    }

    // Only an answer to an ask that had a cause of its own earns the next free re-ask.
    void answered()
    {
        std::function<void()> tell;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            lastAnswered_ = true;
            armed_ = armed_ || !reasking_;
            reasking_ = false;
            serverDownNext_ = ServerDownPause::eFirst;
            tell = onAnswered_;
        }
        if (tell) {
            tell();
        }
    }

    // After a failed ask: returns once the next ask has a cause. facadeAnew asks the netDb.
    MailWaitCause awaitCause(const std::function<bool()>& facadeAnew)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (stopped_) {
                return MailWaitCause::eStopped;
            }
            serverDownNext_ = ServerDownPause::eFirst;
            if (followsAnswer_ && armed_) {
                armed_ = false;
                reasking_ = true;
                return MailWaitCause::eHeldWaitBroke;
            }
            reasking_ = false;
            if (const std::optional<MailWaitCause> cause = causeLocked()) {
                return *cause;
            }
        }
        if (i2p::networkDown()) {
            return awaitNetwork();
        }
        const bool anew = facadeAnew && facadeAnew();
        std::unique_lock<std::mutex> lock(mutex_);
        if (stopped_) {
            return MailWaitCause::eStopped;
        }
        if (anew) {
            return MailWaitCause::eNewerLeaseSet;
        }
        std::optional<MailWaitCause> cause;
        if (!changed_.wait_for(lock, staleBound_, [this, &cause]() {
                cause = stopped_ ? std::optional<MailWaitCause>(MailWaitCause::eStopped)
                                 : causeLocked();
                return cause.has_value();
            })) {
            return MailWaitCause::eStaleLeaseSet;
        }
        return *cause;
    }

    // After the facade answered that its server is down: no lease set is in question then.
    MailWaitCause awaitServer()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        reasking_ = false;
        const std::chrono::milliseconds pause = serverDownPauseLocked();
        std::optional<MailWaitCause> cause;
        if (!changed_.wait_for(lock, pause, [this, &cause]() {
                cause = stopped_ ? std::optional<MailWaitCause>(MailWaitCause::eStopped)
                                 : causeLocked();
                return cause.has_value();
            })) {
            return MailWaitCause::eServerPauseOver;
        }
        return *cause;
    }

private:
    enum class ServerDownPause { eFirst, eSecond, eSteady };

    // No lease set ages while there is no network: only its return is a cause.
    MailWaitCause awaitNetwork()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        std::optional<MailWaitCause> cause;
        changed_.wait(lock, [this, &cause]() {
            cause = stopped_ ? std::optional<MailWaitCause>(MailWaitCause::eStopped)
                             : causeLocked();
            return cause.has_value();
        });
        return *cause;
    }

    std::chrono::milliseconds serverDownPauseLocked()
    {
        switch (serverDownNext_) {
            case ServerDownPause::eFirst:
                serverDownNext_ = ServerDownPause::eSecond;
                return serverDownPauses_.first;
            case ServerDownPause::eSecond:
                serverDownNext_ = ServerDownPause::eSteady;
                return serverDownPauses_.second;
            case ServerDownPause::eSteady: return serverDownPauses_.steady;
        }
        return serverDownPauses_.steady;
    }

    std::optional<MailWaitCause> causeLocked() const
    {
        if (i2p::carryReturns() != carryAtAsk_) {
            return MailWaitCause::eLinkBack;
        }
        if (registered_) {
            return MailWaitCause::eRegistered;
        }
        if (serverAnswered_) {
            return MailWaitCause::eServerAnswered;
        }
        return std::nullopt;
    }

    void wake()
    {
        // The waiter tests the carry under this lock: taking it reaches one about to sleep.
        {
            const std::lock_guard<std::mutex> lock(mutex_);
        }
        changed_.notify_all();
    }

    const std::chrono::milliseconds staleBound_;
    const ServerDownPauses serverDownPauses_;
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    bool stopped_ = false;
    bool serverAnswered_ = false;
    bool registered_ = false;
    bool followsAnswer_ = false;
    bool lastAnswered_ = false;
    bool armed_ = false;
    bool reasking_ = false;
    ServerDownPause serverDownNext_ = ServerDownPause::eFirst;
    std::uint64_t carryAtAsk_ = 0;
    std::function<void()> onAnswered_;
    // Last, so it goes first and no listener outlives the members it touches.
    i2p::CarryWatch carry_;
};

}  // namespace bazarish::client
