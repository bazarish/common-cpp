// Bazarish project (c) 2026
#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace bazarish {

// What a service exits with when an operator asked it to restart from the admin
// panel. It is not zero on purpose: a unit with the usual `Restart=on-failure`
// then starts the service again, so the same code works whether the operator's
// unit says on-failure or always. The panel is the only caller, and the request
// is operator-signed.
inline constexpr int kRestartExitCode = 90;

// What a daemon's threads are stopped by: the flag a main() parks on until the
// service ends, and the one a background sweep sleeps against so shutdown is
// immediate rather than one interval away.
//
// The flag does not live in the HTTP engine because a stop can arrive before the
// listener is bound - a signal during start-up - and it still has to be
// remembered.
class StopGate {
public:
    // Parks the caller until stop(), returning at once when stop() already came.
    void wait();
    // Parks for at most `timeout`; true when the service is stopping.
    bool waitFor(std::chrono::nanoseconds timeout);
    void stop();
    bool stopped() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool stopped_ = false;
};

// Stops a service on somebody else's thread.
//
// A restart is asked for inside a request handler, and a handler must not stop
// the server it is answering on: the response is still unwritten, and the stop
// runs into the dispatch it was called from. So the switch parks a thread of its
// own, and the handler only flips it - the answer goes out, and the stop happens
// a moment later from a thread with nothing else to do.
class RestartSwitch {
public:
    // `stop` is what ends the service's own listen loop.
    explicit RestartSwitch(std::function<void()> stop);
    ~RestartSwitch();

    RestartSwitch(const RestartSwitch&) = delete;
    RestartSwitch& operator=(const RestartSwitch&) = delete;

    // Called from a request handler. Returns at once.
    void request();

    // Whether a restart was asked for, so main() can exit with the code that
    // tells the service manager to start it again.
    bool requested() const;

private:
    std::function<void()> stop_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool asked_ = false;
    bool releasing_ = false;
    std::thread waiter_;
};

}  // namespace bazarish
