// Bazarish project (c) 2026
#pragma once

#include "Client.hpp"

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace bazarish::client {

// Keeps one held overview request while the page that shows it is open.
class OverviewWatch {
public:
    struct Hooks {
        // Empty `since` asks at once; otherwise the answer waits for another version.
        std::function<AccountOverview(const std::string& since)> ask;
        // Ends a held ask from another connection of the same device.
        std::function<void()> release;
        std::function<void(const AccountOverview& overview)> fresh;
        std::function<void(const std::string& reason)> failed;
    };

    explicit OverviewWatch(Hooks hooks);
    ~OverviewWatch();

    OverviewWatch(const OverviewWatch&) = delete;
    OverviewWatch& operator=(const OverviewWatch&) = delete;

    void open();
    void close();
    // The server answered another request after an ask of this watch failed.
    void linkBack();

private:
    void run();

    const Hooks hooks_;
    std::mutex mutex_;
    std::condition_variable wake_;
    bool stopping_ = false;
    bool open_ = false;
    bool parked_ = false;
    bool holding_ = false;
    std::uint64_t opened_ = 0;
    std::uint64_t answeredOpening_ = 0;
    std::string version_;
    std::thread thread_;
};

}  // namespace bazarish::client
