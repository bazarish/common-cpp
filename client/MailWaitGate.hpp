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

namespace bazarish::client {

enum class MailWaitCause {
    eStopped,
    eHeldWaitBroke,
    eLinkBack,
    eServerAnswered,
    eRegistered,
    eNewerLeaseSet,
    eStaleLeaseSet,
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
    }
    return "unknown";
}

// What a mail wait that failed waits for before it asks again; never a period of its own.
class MailWaitGate {
public:
    explicit MailWaitGate(const std::chrono::milliseconds staleBound = kStaleLeaseSetBound)
        : staleBound_(staleBound)
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

    // Only an answer to an ask that had a cause of its own earns the next free re-ask.
    void answered()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        lastAnswered_ = true;
        armed_ = armed_ || !reasking_;
        reasking_ = false;
    }

    // After a failed ask: returns once the next ask has a cause. facadeAnew asks the netDb.
    MailWaitCause awaitCause(const std::function<bool()>& facadeAnew)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (stopped_) {
                return MailWaitCause::eStopped;
            }
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

private:
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
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    bool stopped_ = false;
    bool serverAnswered_ = false;
    bool registered_ = false;
    bool followsAnswer_ = false;
    bool lastAnswered_ = false;
    bool armed_ = false;
    bool reasking_ = false;
    std::uint64_t carryAtAsk_ = 0;
    // Last, so it goes first and no listener outlives the members it touches.
    i2p::CarryWatch carry_;
};

}  // namespace bazarish::client
