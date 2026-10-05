// Bazarish project (c) 2026
#include "OutboundCourier.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/FederationFrame.hpp>

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace {

class ScriptedStream final : public DeliveryStream {
public:
    ScriptedStream(std::string reply, const bool answer)
        : reply_(std::move(reply))
        , answer_(answer)
    {
    }

    void writeAll(const void* const data, const std::size_t size) override
    {
        const auto* const in = static_cast<const std::uint8_t*>(data);
        written_.insert(written_.end(), in, in + size);
    }

    void readExact(void* const buffer, const std::size_t size) override
    {
        if (!answer_) {
            throw std::runtime_error("no answer");
        }
        if (sent_ == 0) {
            reply_.push_back('\n');
        }
        CHECK(sent_ + size <= reply_.size());
        std::memcpy(buffer, reply_.data() + sent_, size);
        sent_ += size;
    }

    void close() override { answer_ = false; }

    const Bytes& written() const { return written_; }

private:
    Bytes written_;
    std::string reply_;
    std::size_t sent_ = 0;
    bool answer_ = true;
};

std::string signedDeliveredReply(const Key& signingKey, const std::string& deliveryId)
{
    const Bytes signedBytes(deliveryId.begin(), deliveryId.end());
    const nlohmann::json reply = {
        {"delivered", true},
        {"deliveryId", deliveryId},
        {"signerPub", toBase64(signingKey.publicDer())},
        {"sig", toBase64(bazarish::sign(signingKey, signedBytes))},
    };
    return reply.dump();
}

DeliverySchedule quickSchedule()
{
    DeliverySchedule schedule;
    schedule.dial = std::chrono::seconds{1};
    schedule.retryDelays
        = {std::chrono::seconds{0}, std::chrono::seconds{0}, std::chrono::seconds{0}};
    schedule.run = std::chrono::seconds{10};
    return schedule;
}

OutboundCourier::Task taskTo(const std::string& dest, const std::string& deliveryId)
{
    OutboundCourier::Task task;
    task.toDest = dest;
    task.deliveryId = deliveryId;
    task.sealed = Bytes{1, 2, 3};
    task.payload = Bytes(64, 0x41);
    return task;
}

}  // namespace

int main()
{
    const Key signingKey = Key::generateSigning();
    const std::string dest = "recipient.b32.i2p";

    {
        std::vector<std::string> phases;
        int dials = 0;
        OutboundCourier courier([](const std::string&, const std::string&) { return true; },
            [&](const std::string&, std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                ++dials;
                return std::make_shared<ScriptedStream>(
                    signedDeliveredReply(signingKey, "d-1"), true);
            },
            quickSchedule());
        OutboundCourier::Task task = taskTo(dest, "d-1");
        task.onPhase = [&phases](const std::string& phase) { phases.push_back(phase); };
        const OutboundCourier::Outcome outcome = courier.deliverNow(task);
        CHECK(outcome.stored);
        CHECK(dials == 1);
        CHECK(phases.size() == 3);
        CHECK(phases.at(0) == kPhasePreparing);
        CHECK(phases.at(1) == kPhaseDialing);
        CHECK(phases.at(2) == kPhaseSending);
    }

    {
        int dials = 0;
        OutboundCourier courier([](const std::string&, const std::string&) { return true; },
            [&](const std::string&, std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                ++dials;
                return std::make_shared<ScriptedStream>(
                    nlohmann::json({{"delivered", true}}).dump(), true);
            },
            quickSchedule());
        const OutboundCourier::Outcome outcome = courier.deliverNow(taskTo(dest, "d-2"));
        CHECK(!outcome.stored);
        CHECK(dials == kDeliveryAttempts);
    }

    {
        int dials = 0;
        std::vector<std::string> retries;
        OutboundCourier courier([](const std::string&, const std::string&) { return true; },
            [&](const std::string&, std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                ++dials;
                return nullptr;
            },
            quickSchedule());
        OutboundCourier::Task task = taskTo(dest, "d-3");
        task.onPhase = [&retries](const std::string& phase) {
            if (phase.rfind(kPhaseRetryPrefix, 0) == 0) {
                retries.push_back(phase);
            }
        };
        const OutboundCourier::Outcome outcome = courier.deliverNow(task);
        CHECK(!outcome.stored);
        CHECK(dials == kDeliveryAttempts);
        CHECK(static_cast<int>(retries.size()) == kDeliveryAttempts - 1);
        CHECK(retries.front() == std::string(kPhaseRetryPrefix) + "2/4");
        CHECK(outcome.errorCode == "RECIPIENT_SERVER_UNREACHABLE");
    }

    {
        int dials = 0;
        std::vector<std::string> retries;
        DeliverySchedule schedule = quickSchedule();
        schedule.dial = std::chrono::seconds{2};
        schedule.run = std::chrono::seconds{5};
        OutboundCourier courier([](const std::string&, const std::string&) { return true; },
            [&](const std::string&, const std::chrono::seconds forHowLong)
                -> std::shared_ptr<DeliveryStream> {
                ++dials;
                std::this_thread::sleep_for(forHowLong);
                return nullptr;
            },
            schedule);
        OutboundCourier::Task task = taskTo(dest, "d-budget");
        task.onPhase = [&retries](const std::string& phase) {
            if (phase.rfind(kPhaseRetryPrefix, 0) == 0) {
                retries.push_back(phase);
            }
        };
        const OutboundCourier::Outcome outcome = courier.deliverNow(task);
        CHECK(!outcome.stored);
        CHECK(dials == 2);
        CHECK(static_cast<int>(retries.size()) == dials - 1);
        CHECK(outcome.errorCode == "RECIPIENT_SERVER_UNREACHABLE");
        CHECK(outcome.errorMessage.find("2 of 4 tries") != std::string::npos);
    }

    {
        OutboundCourier courier([](const std::string&, const std::string&) { return true; },
            [&](const std::string&, std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                return std::make_shared<ScriptedStream>(std::string(), false);
            },
            quickSchedule());
        const OutboundCourier::Outcome outcome = courier.deliverNow(taskTo(dest, "d-quiet"));
        CHECK(!outcome.stored);
        CHECK(outcome.errorCode == "RECIPIENT_SERVER_UNREACHABLE");
        CHECK(outcome.errorMessage.find("did not answer") != std::string::npos);
    }

    {
        int dials = 0;
        OutboundCourier courier([](const std::string&, const std::string&) { return true; },
            [&](const std::string&, std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                ++dials;
                return std::make_shared<ScriptedStream>(
                    nlohmann::json({{"delivered", false}, {"errorCode", "DELIVERY_REJECTED"},
                        {"errorMessage", "delivery rejected"}})
                        .dump(),
                    true);
            },
            quickSchedule());
        const OutboundCourier::Outcome outcome = courier.deliverNow(taskTo(dest, "d-4"));
        CHECK(!outcome.stored);
        CHECK(dials == 1);
        CHECK(outcome.errorCode == "DELIVERY_REJECTED");
    }

    {
        int dials = 0;
        OutboundCourier courier([](const std::string&, const std::string&) { return false; },
            [&](const std::string&, std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                ++dials;
                return nullptr;
            },
            quickSchedule());
        const OutboundCourier::Outcome outcome = courier.deliverNow(taskTo(dest, "d-5"));
        CHECK(!outcome.stored);
        CHECK(dials == 0);
        CHECK(!outcome.errorMessage.empty());
    }

    {
        std::mutex mutex;
        std::condition_variable cv;
        int inFlightSame = 0;
        int maxInFlightSame = 0;
        int otherDials = 0;
        bool release = false;
        OutboundCourier courier([](const std::string&, const std::string&) { return true; },
            [&](const std::string& toDest,
                std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
                std::unique_lock<std::mutex> lock(mutex);
                if (toDest == "other.b32.i2p") {
                    ++otherDials;
                    cv.notify_all();
                } else {
                    ++inFlightSame;
                    maxInFlightSame = std::max(maxInFlightSame, inFlightSame);
                    cv.notify_all();
                    cv.wait(lock, [&release]() { return release; });
                    --inFlightSame;
                }
                return std::make_shared<ScriptedStream>(
                    signedDeliveredReply(signingKey, "d-6"), true);
            },
            quickSchedule());
        courier.submit(taskTo(dest, "d-6"));
        courier.submit(taskTo(dest, "d-6"));
        courier.submit(taskTo("other.b32.i2p", "d-6"));
        {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [&otherDials]() { return otherDials == 1; });
            release = true;
        }
        cv.notify_all();
        courier.stop();
        CHECK(maxInFlightSame == 1);
        CHECK(otherDials == 1);
    }

    std::printf("TestOutboundCourier ok\n");
    return 0;
}
