// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
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
    eSilencePauseOver,
    eServerPauseOver,
};

enum class FacadeLookup { eNewer, eSame, eMissing };

inline FacadeLookup facadeLookupOf(const i2p::LeaseSetRefresh& refresh)
{
    if (!refresh.after.has_value()) {
        return FacadeLookup::eMissing;
    }
    return i2p::publishedLater(*refresh.after, refresh.before) ? FacadeLookup::eNewer
                                                               : FacadeLookup::eSame;
}

// The local destination a mail wait reaches its facade from, and the facade's address.
struct FacadeLink {
    std::string localHost;
    std::string remoteHost;
};

struct FacadeLookups {
    std::function<FacadeLookup()> lookUp;
    FacadeLink link;
};

// After a silent ask: a pause, a lookup of the facade's lease set, a pause, the next ask.
inline constexpr std::chrono::seconds kSilentAskPause{5};
// No lease set of the facade to be found: only the lookup repeats, at this pause.
inline constexpr std::chrono::seconds kMissingLeaseSetPause{10};
inline constexpr std::chrono::seconds kLongSilence{180};
inline constexpr std::chrono::seconds kLongSilencePause{60};

struct SilencePauses {
    std::chrono::milliseconds ask{kSilentAskPause};
    std::chrono::milliseconds missing{kMissingLeaseSetPause};
    std::chrono::milliseconds longSilence{kLongSilence};
    std::chrono::milliseconds longPause{kLongSilencePause};
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
        case MailWaitCause::eSilencePauseOver: return "the pause after a silent ask is over";
        case MailWaitCause::eServerPauseOver:
            return "the pause after the facade found its server down is over";
    }
    return "unknown";
}

// What a mail wait that failed waits for before it asks again.
class MailWaitGate {
public:
    explicit MailWaitGate(const SilencePauses silencePauses = SilencePauses(),
        const ServerDownPauses serverDownPauses = ServerDownPauses())
        : silencePauses_(silencePauses)
        , serverDownPauses_(serverDownPauses)
        , asked_([this](const i2p::AskedLookup& asked) { told(asked); })
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
        silentSince_.reset();
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
            silentSince_.reset();
            tell = onAnswered_;
        }
        if (tell) {
            tell();
        }
    }

    // After a failed ask: returns once the next ask has a cause. A lookup asked by hand on the
    // same way to the facade meanwhile stands for the next lookup of its own.
    MailWaitCause awaitCause(const FacadeLookups& facade)
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
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (!silentSince_.has_value()) {
                silentSince_ = std::chrono::steady_clock::now();
            }
            cycleOn_ = facade.link;
            told_.reset();
        }
        const MailWaitCause cause = cycle(facade);
        const std::lock_guard<std::mutex> lock(mutex_);
        cycleOn_.reset();
        told_.reset();
        return cause;
    }

    // After the facade answered that its server is down: no lease set is in question then.
    MailWaitCause awaitServer()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        reasking_ = false;
        silentSince_.reset();
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

    MailWaitCause cycle(const FacadeLookups& facade)
    {
        Woken woken = pause(silencePauses_.ask);
        for (;;) {
            if (woken.cause.has_value()) {
                return *woken.cause;
            }
            const FacadeLookup found = woken.told.has_value() ? *woken.told
                : facade.lookUp                              ? facade.lookUp()
                                                             : FacadeLookup::eSame;
            if (found == FacadeLookup::eNewer) {
                return MailWaitCause::eNewerLeaseSet;
            }
            const bool missing = found == FacadeLookup::eMissing;
            woken = pause(missing ? silencePauses_.missing : silencePauses_.ask);
            if (!woken.cause.has_value() && !woken.told.has_value() && !missing) {
                return MailWaitCause::eSilencePauseOver;
            }
        }
    }

    struct Woken {
        std::optional<MailWaitCause> cause;
        std::optional<FacadeLookup> told;
    };

    // What ended the pause early: a cause, or a lookup asked by hand. Neither once it is over.
    Woken pause(const std::chrono::milliseconds wanted)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const bool longSilent = silentSince_.has_value()
            && std::chrono::steady_clock::now() - *silentSince_ >= silencePauses_.longSilence;
        Woken woken;
        changed_.wait_for(lock, longSilent ? silencePauses_.longPause : wanted, [this, &woken]() {
            woken.cause = stopped_ ? std::optional<MailWaitCause>(MailWaitCause::eStopped)
                                   : causeLocked();
            return woken.cause.has_value() || told_.has_value();
        });
        woken.told = told_;
        told_.reset();
        return woken;
    }

    void told(const i2p::AskedLookup& asked)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (!cycleOn_.has_value() || cycleOn_->localHost.empty()
                || asked.localHost != cycleOn_->localHost
                || asked.remoteHost != cycleOn_->remoteHost) {
                return;
            }
            told_ = facadeLookupOf(asked.refresh);
        }
        changed_.notify_all();
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

    const SilencePauses silencePauses_;
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
    std::optional<std::chrono::steady_clock::time_point> silentSince_;
    std::optional<FacadeLink> cycleOn_;
    std::optional<FacadeLookup> told_;
    std::function<void()> onAnswered_;
    // Last, so they go first and no listener outlives the members it touches.
    i2p::AskedLookupWatch asked_;
    i2p::CarryWatch carry_;
};

}  // namespace bazarish::client
