// Bazarish project (c) 2026
#include "OverviewWatch.hpp"

#include <bazarish/Log.hpp>

#include <utility>

namespace bazarish::client {

OverviewWatch::OverviewWatch(Hooks hooks)
    : hooks_(std::move(hooks))
    , thread_([this]() { run(); })
{
}

OverviewWatch::~OverviewWatch()
{
    bool held = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
        held = holding_;
    }
    wake_.notify_all();
    if (held) {
        hooks_.release();
    }
    thread_.join();
}

void OverviewWatch::open()
{
    bool held = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        open_ = true;
        parked_ = false;
        ++opened_;
        held = holding_;
    }
    wake_.notify_all();
    // A release sent before the closed page's hold reached the server leaves that hold behind.
    if (held) {
        hooks_.release();
    }
}

void OverviewWatch::close()
{
    bool held = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        open_ = false;
        held = holding_;
    }
    if (held) {
        hooks_.release();
    }
}

void OverviewWatch::linkBack()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        parked_ = false;
    }
    wake_.notify_all();
}

void OverviewWatch::run()
{
    for (;;) {
        std::string since;
        std::uint64_t opening = 0;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            wake_.wait(lock, [this]() { return stopping_ || (open_ && !parked_); });
            if (stopping_) {
                return;
            }
            opening = opened_;
            // The first ask of an opening draws the page, so it is not held.
            since = opening == answeredOpening_ ? version_ : std::string();
            holding_ = !since.empty();
        }
        try {
            const AccountOverview answer = hooks_.ask(since);
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                holding_ = false;
                version_ = answer.version;
                answeredOpening_ = opening;
                if (stopping_) {
                    return;
                }
            }
            if (answer.version != since) {
                hooks_.fresh(answer);
            }
        } catch (const std::exception& error) {
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                holding_ = false;
                version_.clear();
                if (stopping_) {
                    return;
                }
                parked_ = true;
            }
            bazarish::log::info("the overview of the account is not known: {}", error.what());
            hooks_.failed(error.what());
        }
    }
}

}  // namespace bazarish::client
